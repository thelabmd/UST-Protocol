<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# UST 1.0 — Formal Model (NON-NORMATIVE Appendix)

> **You don't have to read this — and you don't have to think about it at all.** Nothing here is needed to use UST.
> To publish, to verify, or to build a client in any language, you need only the normative spec (`UST-1.0.md`), the
> reference code, and the conformance vectors. This document is for people who want to see *why the ground is solid*,
> not just take our word that it is. If that isn't you today, skip it with a clear conscience — you lose nothing
> operational.
>
> Here's the part worth knowing even if you never scroll past this line: on our side, every claim below is held to a
> strict **math → code → vector → test** correspondence. Each theorem points at a real test that runs in our build,
> a guard breaks the build if a theorem ever cites a check that isn't there, and each check is pinned by a
> language-neutral vector anyone can run. So the math isn't decoration and it isn't a promise — it's wired to the
> exact same tests your own implementation would run. That link is what lets UST be rebuilt in **any language**:
> you check the vectors, never our prose.

**TWO RULES THIS MODEL DOES NOT TRADE AWAY**, stated at the top because several sections below are special cases
of them.

**A minor only ADDS; a meaning-change is a MAJOR.** An older verifier evaluating under older rules must still be
RIGHT about what it evaluated — otherwise a minor leaves every deployed verifier quietly wrong rather than merely
less informed, and wrongness indistinguishable from health is the failure this whole model exists to exclude.

**A verifier never expires.** Newer material an older verifier does not implement is an UNATTEMPTED axis
(F.5p.2), never an invalid document and never a silent pass. Sufficiency is the consumer's policy, not the
protocol's coercion — see F.5p.1 for the same partition one level down, on the profile, where an unknown member
of a CLOSED half is refused while an unknown member of the OPEN half is ignored. Versioning is that partition
generalised from one document to the wire.

**A DEFERRAL IS A CLAIM ABOUT SOMETHING THIS DOCUMENT CANNOT SEE.** Every section below ends in a `**Binding:**`
line, and three of its four forms are self-contained: `realized` cites checks that resolve inside this tree, and
`none — <reason>` is judged on its face. `pending — <tracker>` is the exception. It points OUTSIDE, so it is the
one claim whose truth changes without anyone editing this document or the code — the day the tracker closes, the
line becomes false in silence.

It fails in both directions, and neither is visible from in here. If the work shipped, the model UNDERSTATES its
own realization and the citations that would let a reader verify it are never written. If the work did not ship,
the obligation has no owner while still reading as owned. A reader asking *what does UST not do yet* is handed
answers of unknown age. Measured 2026-08-13: five of eight pending bindings named issues that were already
closed — the oldest for 15 days — and the only enforcement asked of the reference was that it be three
characters long. CLOSED 2026-08-13 — round 208 (#156): the reference is now resolved against the live tracker.

So a deferral is DEFERRED, never discharged, and two things follow. **It must be resolvable** — the reference is
checked against the live tracker, and a closed tracker forces the line to move, either to `realized` with
citations or to a tracker that is open. Closing an issue is not discharging an obligation; only citations are.
**And it may only be written in the marker form** — a deferral phrased as prose beside a tracker reference is
invisible to the check that resolves it, which is how two of them survived: this very line read *Status: reporting
side pending, #138* for the nine days after #138 closed, and F.5e.1's own `realized` line went on asserting that
#106 *remains open* for fifteen.


> **Status: NON-NORMATIVE.** This appendix gives a measure-theoretic semantics for UST. It defines nothing new:
> every object here is a restatement of a mechanism already fixed in `UST-1.0.md` (the normative text). Where this
> appendix and the normative spec appear to differ, **the normative spec wins** — this is a lens, not a rule.
> Its purpose is rigor: to make the *meaning* of "verify," of the trust tiers, and of "fixation, not truth"
> precise enough to outlive any single implementation, and to give reviewers a formal target.
>
> **Review status (honest, 2026-07-14).** This formal model has been red-teamed iteratively by AI systems acting
> as adversarial auditors (18+ rounds, including three independent measure-theory red-teams), and was EXTENDED on
> 2026-07-14 with the authority-checkpoint theorems (§F.5g–§F.5n) and the assurance product-lattice (§F.5.0). It
> has **not** been machine-checked in a proof assistant, and **no professional human mathematician has refereed it
> yet**. A mechanical `model ↔ code` guard now binds every theorem the model cites to a running conformance check
> (97/97) — this enforces lockstep with the implementation, but it is a CORRESPONDENCE check, **not** a proof of the
> mathematics. The §F.5 error-categories (document-as-data vs world-as-randomness) remain an active area of
> refinement. **Users should treat the model as a conceptual framework, not a theorem.** The open assurance
> gates — an independent measure-theory review and a machine-checked core — are tracked alongside the pending
> human cryptographic audit.

The right mathematical home for *time-ordered, append-only, verifiable-at-a-moment* records is the theory of
**filtrations and adapted processes** (the same apparatus under stochastic processes and stopping times). UST is
the deterministic core of that apparatus; probability enters only at one clearly-marked boundary (§F.8).

---

## F.1 The measurable space of world-states

- Let **Ω** be the space of **world-histories**. A point `ω ∈ Ω` is one complete history of the world (a path),
  not an instantaneous snapshot — this matters because records are time-indexed.
- The value space is **V = Σ\*** — finite UTF-8 strings in NFC (the §5 value model). *Everything* a record carries
  is a point of `V`; numbers, times, and hashes are their string encodings. (This is why canon is
  string-only: the coordinates literally live in `Σ\*`.)
- Each partition/field is a **coordinate map** at a frame `t`:
  `Xᵢ,ₜ : Ω → V`.
  A partition is a measurable coordinate of the world-history — "what the value of field *i* is, at frame *t*."

The world-history carries two further coordinate families, declared here so that every later σ-algebra is
generated by honest random objects on Ω (16th-round rigor pass):
- **`Lₜ : Ω → LogSpace`** — the anchor journal at real time `t` in history `ω`, where **`LogSpace` is the space
  of PARTIAL MAPS `FrameID ⇀ HashSpace`** (which frame slot carries which committed hash — faithful to the real
  journal, which is frame-indexed: one sealed hash per slot, M4). Append-only is a property of the coordinate:
  along every path, `s ≤ t ⇒ Lₛ(ω) ⊑ Lₜ(ω)` (map extension; a substrate entry exists only at its registered
  finality, §11.2 — a rollbackable confirmation is not yet in the map).
- **`W_n : Ω → AuthSpace`**, for each name `n` — the name-authority observables of `n` in history `ω`: which
  genesis/key-log the domain serves, and what independent witnesses observed it serve (§12).

The **base measurable space** is `(Ω, 𝓕)` where `𝓕 := σ( { Xᵢ,ₜ, Lₜ, W_n } )` is the σ-algebra generated by ALL
coordinate maps; every coordinate is `𝓕`-measurable by construction, and every σ-algebra below is a sub-σ-algebra
of `𝓕`. `LogSpace` and `AuthSpace` carry their natural **cylindrical σ-algebras** (generated by the evaluation
maps `L ↦ L(frame)` and the coordinate projections of `AuthSpace`), so evaluations of the journal are measurable
functions of it. Time indices range over the protocol's DISCRETE frame grid `𝕋` (30-second slots and their
coarsenings) — continuous-time pathologies (right-continuity, usual conditions) do not arise.

A **state** at frame `t` is the tuple `(X₁,ₜ, …, Xₙ,ₜ)`; a **record** (transcript) `R` is a publisher's signed
commitment to the observed values of that tuple.

**Binding: none — definitional.** It fixes the ambient objects (Ω, the coordinate random variables) that every later section quantifies over; no party owes code for a naming of the ambient space.

## F.1.1 The partition-kind domain `K` is one object, and fail-closed is only sound relative to it (#154)

F.1 gives each partition a value in `V`; it does not say what a partition ASSERTS about how that value came to be.
That is the kind, and the protocol admits exactly three:

  `K := { captured, computed, absence }`

`captured` = witnessed from the world, `computed` = derived, `absence` = a NEGATIVE observation carrying a reason
(§4.4, #39 — the notary's other half). The kind is a descriptive tag: it is inside the signed bytes and therefore
inside the signature, but it is not an input to `partitionHash`, so it changes no hash.

**The obligation is EQUALITY, not membership.** Let `A_impl ⊆ Σ*` be the kind set an implementation admits. Every
conforming verifier owes `A_impl = K`, and each direction of failure is a verdict flip with opposite sign:

- `A_impl ⊋ K` — admits a kind the protocol never defined. The reader is told a value was witnessed when nothing
  in the standard says what the tag means. Unsound in the accepting direction.
- `A_impl ⊊ K` — refuses a conforming document. Fail-closed on an unknown kind is the correct MECHANISM, but the
  mechanism decides against `A_impl`, not against `K`; a missing element turns a correct refusal into a **false
  INVALID on a valid document**, and the verdict names the publisher rather than the verifier.

This second direction is not hypothetical. Measured 2026-08-13: the browser verifier and the extension enumerated
`{captured, computed}` and returned `E-MALFORMED` on every live document of the reference operator, because each
slot carries `absence` partitions for sources that did not answer. Both implementations were faithful to what they
read; the registry they read from named two kinds while the §4.4 grammar named three. CLOSED 2026-08-13 — round 206
(#154): `K` is named here, realized once as `REGISTRY.partitionKinds`, and every verifier surface is diffed against
it; the page's own call path now returns `VALID:HIGH` on the document that produced the report.

**Why the mechanism could not save it.** *Corollary (naming an instance, again)* in F.5v already fixes the right
shape — enumerate the POSITIVE set, closed and small, everything else blind by default. That shape is sound only
when the positive set is ONE object. Here it was four: the core library, the browser verifier, the extension and
the spec registry each enumerated `K` independently, and no theorem quantified over `K`, so nothing was violated
when they diverged. Per-implementation soundness held throughout; AGREEMENT is a property of the domain, and an
undefined domain cannot carry it.

Hence `K` is named here and realized once, as REGISTRY data: the spec's registry section is generated from it and
the code's literal usage is diffed against it, so the four enumerations become one. A verifier's admitted set is
checkable against `K` — and, separately, the corpus over which two implementations are compared must EXERCISE every
element of `K`, or the comparison is silent on exactly the element they disagree about.

**Binding: realized** — *"#154 the admitted partition-kind domain is EXACTLY the registry set K"* · *"#154 every element of K verifies, and a kind outside K is refused"* · *"#154 the cross-implementation corpus exercises every element of K"*.

## F.2 Measurement vs reality — the origin of "fixation, not truth"

Distinguish two maps into `V`:

- `Yᵢ,ₜ : Ω → V` — the **true** coordinate (what the field actually is).
- `Mᵢ,ₜ : Ω → V` — the **measurement** the publisher recorded (a sensor reading, a computation, a copy-paste).

In general `Mᵢ,ₜ = m(Yᵢ,ₜ, εᵢ,ₜ)` for some measurement map `m` and disturbance `ε` (a wrong sensor, a rounding,
a lie). `V = Σ*` is a space of strings — there is no addition on it; `ε` is an ABSTRACT deviation (the reading
differs from the truth in whatever way), not an additive noise term.

**A UST record binds `Mᵢ,ₜ`, never `Yᵢ,ₜ`.** It fixes *the measurement the publisher committed to, including its
error*. This is the entire content of "fixation, not truth" (§1): the protocol certifies `M`, and is silent on
the deviation between `M` and `Y`. Accountability follows — you learn *which publisher committed which `M` at which `t`* — but truth
(`Y`) is out of scope by construction.

**Binding: none — definitional.** It separates a measurement from the reality it measures — the framing that makes "fixation, not truth" precise. Nothing here is an obligation on an implementation.

## F.3 The anchor journal is a filtration

Let the external append-only log (the anchor substrate, §11) define, for each real time `t`:

  **Fₜ := σ( Lᵤ : u ≤ t ),**  the σ-algebra generated by the JOURNAL COORDINATE SUB-PROCESS up to `t` — the
  family of maps `{ Lᵤ }_{u ≤ t}` from F.1, NOT the current set `Lₜ` alone (a snapshot forgets WHEN each hash
  entered, and `σ` of a single set does not recover the past — the two-independent-red-team fix, 17th round).
  The atomic events are `E_{h,u} := { ω : h ∈ Lᵤ(ω) }`; "the log" is the explicit F.1 coordinate, no
  self-reference remains.

**Proposition F.3 (Fₜ is a filtration).** `{Fₜ}` is a filtration: each `Fₜ` is a σ-algebra, and `s ≤ t ⇒ Fₛ ⊆ Fₜ`.

*Proof.* Each `Fₜ` is generated by a family of measurable maps, hence a σ-algebra. For `s ≤ t` the generating
FAMILY nests literally — `{ Lᵤ }_{u ≤ s} ⊆ { Lᵤ }_{u ≤ t}` — and the σ-algebra generated by a larger family of
maps contains the one generated by a sub-family; therefore `Fₛ ⊆ Fₜ`. (This is the correct move: the earlier
"`Lₛ ⊆ Lₜ` hence `σ(Lₛ) ⊆ σ(Lₜ)`" was the classic `A ⊆ B ⇏ σ(A) ⊆ σ(B)` trap — repaired by generating from the
history `{Lᵤ}` rather than from one set.) ∎

**Corollary F.3.1 (un-backdatable time).** Backdating is the false claim that a hash `h` was present earlier
than it was. It is refuted not by a meta-statement about algebra membership but by an EVENT in the realized
history `ω*`: a historical checkpoint witnesses `ω* ∉ E_{h,t₀}` (h absent by `t₀`) yet `ω* ∈ E_{h,t₁}` (present
by `t₁`), so the earliest provable existence is `t₁`, never `t₀`. The index `t` of `{Fₜ}` is REAL time as
attested by the anchor substrate (§11) — the filtration is not merely ordered, it is TIME-STAMPED by an external
base the verifier
already trusts. Monotonicity alone orders events; the substrate's time base pins the order to the calendar —
both together give un-backdatability, stated purely in EVENT form: the truth-values `ω* ∉ E_{h,t₀}` and
`ω* ∈ E_{h,t₁}` in the realized history (never "membership of an algebra", which is a meta-fact, not a world
event). One honest caveat (18th round): an inclusion-only Merkle log proves "existed BY `t₁`" but cannot by
itself prove "ABSENT at `t₀`" — refuting a backdating claim needs **authenticated non-membership** (a complete
verifiable snapshot at `t₀`, or a non-membership proof). Without a valid `t₀` receipt, backdating is
UNCONFIRMED; with authenticated non-membership it is REFUTED. (The reference journal is a per-hour COMPLETE
snapshot — every slot of the hour listed — so non-membership there is checkable by construction.) This is
exactly why a **retro-seal after an outage is fatal** — against a snapshot-complete journal it is a provably
false claim about the realized history, not a mere policy breach.

**Binding: none — substrate-assumption.** Monotonicity of the anchor journal (`F_s ⊆ F_t`, an entry never leaves) is REQUIRED OF the substrate profile (§17) and probed through `substrateVerify`; the checker cannot enforce a foreign log's append-only discipline, so a checker-side binding here would be the overclaim. The part UST does enforce — chain linkage and well-foundedness — is realized in F.5h.

**The membership relation itself is a substrate assumption too (rev91, #95).** `Fₜ` is generated by the anchored leaf-SETS `A_auth(h)`, and the model's statements quantify over the relation `content_hash ∈ leaves(A_auth(h))` — never over the tree that decides it. Which hash construction realizes that relation belongs to the PUBLISHER, exactly as the finality parameter belongs to the substrate.

**CORRECTION (same day, rev91).** This paragraph first grounded the argument in `rekor`, claiming its registry entry made a REGISTERED substrate unsatisfiable against §11.2. That was wrong, and the error was conflating two trees. An anchor carries TWO independent proofs: `content_hash → root` in the publisher's own tree, and then `root` committed under the substrate's profile. `rekor`'s `inclusionProof` belongs to the SECOND — it proves the logged entry (which attests our root) is in rekor's tree, and the shipped `rekor` connector already binds it that way. It is never the path from `content_hash`. So §17 and §11.2 were not in contradiction as written.

The delegation is nonetheless necessary, for a reason the operator's own record had already stated four days earlier: a publisher committing hours with an RFC 6962 tree over raw digests (leaf `SHA256(0x00‖·)`, node `SHA256(0x01‖L‖R)`) cannot express those paths as `ust:leaf`/`ust:node` over ASCII `sha256:`-prefixed strings (§7). A core fixing ONE construction forces a SECOND tree over the same leaves, built solely to satisfy the verifier — which is what the reference operator's migration plan had budgeted for. So the membership construction is the FOURTH thing a §17 entry may pin, alongside the `Locator` fields, the public-append-only-log check and the finality parameter, and it is probed through `inclusionVerify` exactly as monotonicity is probed through `substrateVerify`.

What this costs, stated rather than glossed: inclusion used to be BYTE-MEASURABLE with zero configuration — any two parties agreed from the proof bytes alone. It is now measurable with respect to (bytes × declared profile). That is a strictly weaker claim, and the weakening is real. It introduces no NEW assumption class: the substrate half of the anchor already lived here, and §11.2 already requires that the substrate be REGISTERED with a DETERMINISTIC procedure and DECLARED by the operator (§20), so two consumers loading the same declared profile still agree. Inter-consumer agreement is now conditional on that declaration — the same condition the finality parameter has always carried.

The ENFORCEMENT that makes this delegation safe is not stated here — an assumption section binds nothing by construction. It is F.5c.1.

## F.4 Streams are adapted processes

Model the publisher's emission as a **DocSpace-valued process** `Rₜ : Ω → DocSpace ∪ {⊥}` (⊥ = no frame at
`t`). Define the **commitment process** `Hₜ(ω) := Lₜ(ω)(frameₜ)` — the journal's entry AT this frame (`Hₜ := ⊥`
where the map is undefined). Because the journal is frame-indexed (F.1) and `LogSpace` carries the cylindrical
σ-algebra, `Hₜ = evalₜ ∘ Lₜ` is a measurable function OF THE JOURNAL, so `σ(Hₜ) ⊆ Fₜ` holds as a theorem, not
an assertion. (Mere membership `contentHash(Rₜ(ω)) ∈ range Lₜ(ω)` would NOT suffice — a set-valued journal
cannot single out WHICH element is this frame's hash; the frame-indexed journal is what makes the commitment
process genuinely adapted — 18th-round fix.) For a verifier the useful statement is the fixed-`d` form: for a
concrete received document `d`, the ANCHORING FACT `A_{d,t} := { ω : contentHash(d) ∈ range Lₜ(ω) }` is an
event in `Fₜ`. The FULL document `Rₜ` is NOT `Fₜ`-measurable — a hash does not reveal its preimage (this is
UST's design: the anchor fixes that bytes EXISTED, it neither stores nor discloses them; §11.2). `Rₜ` is
adapted only to the richer **base world filtration** `𝒢ₜ := Fₜ ∨ σ( Rᵤ : u ≤ t )`; `σ(Rₜ) ⊆ 𝒢ₜ` by
construction, and `𝒢ₛ ⊆ 𝒢ₜ` since both components accumulate monotonically. `prev` binds `Rₜ` to `Rₜ₋₁` inside
this filtration. **Completeness over `[t₀, t₁]`** is a RANGE property (a
verdict of `verifyStream` over an interval, §11.3) — a single document's tier never asserts it. It is the statement that
the observed adapted process has *no missing frame* in the interval — an `F_{t₁}`-measurable assertion witnessed by
a covering stream checkpoint (`M5`). "The stream is complete" = "this adapted process is fully observed up to the
stopping time `t₁`."

**Completeness is authenticated coverage of a committed grid — no-deletion is not no-omission (M5, made precise).**
The `prev`-chain establishes a TOTAL ORDER on the observed frames and forecloses DELETION from a shown chain
(removing frame `t` orphans `t+1`'s `prev`), but it does NOT by itself foreclose OMISSION: a publisher that never
emits frame `t` and links `t+1.prev = t-1` yields a self-consistent chain WITH A HOLE. Chain-consistency and
completeness are therefore different σ-algebras — the former is `σ(prev-links)`, the latter needs the EXPECTED
index set — and by Corollary F.3.1 "no frame is missing" is exactly an **authenticated non-membership** claim on
the frame axis, which does not follow from the positive `prev`-links alone. The missing coordinate is the
publisher's **cadence** `c_n(t)`, modelled as a signed, time-resolved parameter — itself an adapted process,
resolved at `t` EXACTLY as the key-log resolves the active key at `t` (§12.2), so it cannot be shrunk post-hoc to
a coarser grid that hides slots. Then the expected grid over a closed interval is DETERMINISTIC,
`G(n,t₀,t₁) := { the ust_id grid points of spacing c_n over [t₀,t₁] }`, and `expected_slot_count := |G|` is a
DERIVED quantity, never stored. Define **complete over `[t₀,t₁]`**: for every `g ∈ G` the observed set contains
either a frame with `ust_id = g` OR a signed gap record (§11.1) covering `g`, witnessed by a covering stream checkpoint
committing `(t₀, t₁, head, cumulative_count)`. This event is `F_{t₁}`-measurable **only when** `c_n(t) ∈ ℐ`:
without the signed cadence `|G|` is unknown, so `frame_count = |observed|` cannot be compared to `|G|`, and the
honest verdict is the strictly coarser **chain-consistent** (no-deletion), never **complete**. Note what does NOT
change: the stream checkpoint is the existing `class:"attestation"` with two interval bounds added to its value, the
grid is COMPUTED not stored, and the gap record already exists (§11.1) — completeness is earned by adding the
cadence coordinate to `ℐ`, not by any new document shape.

**Realization (rev92 — a graded verdict is closed under its own axis; a report is not).** Making the grid REACHABLE (rev91) at once created the temptation to GRADE it. The §20.1 discovery attestation gained a cadence probe, and because that attestation withholds `ATTESTED` on any property it could not check, a publisher that deliberately declares no grid became permanently non-conformant. The defect is not one of severity but of ALGEBRA: §20.1 ranges over the serving contract — is the identity fetchable, byte-stable, independently mirrored — while `c_n(t)` is an input to the RANGE verdict over a stream. They are predicates over disjoint carriers, and neither is a factor of the other. A publisher with no declared cadence is fully §20.1-conformant, and the consequence of its silence lands exactly where it belongs: on the range, which stays `chain-consistent` and can never reach `complete`. Hence the SCORED set of an attestation must be closed under the axis that attestation names, while its REPORTED set may be strictly wider — the operator is shown the whole neighbourhood and graded only on the contract they are actually in. An observation that crosses an axis is informational BY CONSTRUCTION and never by a judgement of how important it seems; the moment importance is what decides, the axis has already been lost.

**Realization (rev91 — the coordinate is OBTAINED, and `ℐ` admits only what is known).** The condition above is exact and needs no case added to it: `c_n(t)` is either IN the information set or it is not. What a transport contributes is which of those two holds, and there are exactly two ways it can answer. A cadence log that is **not served** (404/410) is a determinate answer — the publisher declares no change, so the genesis value is what is known and the coordinate IS in `ℐ` (*"#95/F.4 cadence ABSENT (404) is benign — the publisher declares no change, the document still resolves"*). A log that **exists and cannot be read** answers nothing: the coordinate is simply not in `ℐ`, and the RANGE verdict — the only one `c_n(t)` enters — falls to the coarser rung the section already prescribes (*"#95/F.4 cadence UNREADABLE is never substituted by an empty log — the coordinate is reported UNKNOWN (a wrong value in ℐ would manufacture completeness)"*). "The verdict" was written unqualified here, and round-233 records what an unqualified verdict was read to mean.

The enforcement is therefore not a third case but the CLOSURE of `ℐ` under implementation: an empty log is a VALUE, and writing one in place of an unanswered query would place in `ℐ` something that is not known — which the definition of `ℐ` forbids and no amount of transport handling may loosen. The key-log carries the identical closure, where collapsing unreadable into empty erases a retirement.

**Realization (round-233 — the coordinate's absence is a fact about ONE carrier, and identity is not that carrier).** rev92
settled this algebra for the §20.1 attestation and swept a single surface; discovery is the other surface of the same
mechanism. A transport that cannot read the cadence log removes `c_n(t)` from `ℐ`, and by the definition above that is a
statement about the RANGE: `|G|` is unknown, so `complete` is unreachable and `chain-consistent` is the ceiling. It says
nothing about the identity carrier — the name-binding root, the key log and the witness — and no factorization runs
between the two, so **withholding the identity verdict because the cadence is unknown is the category error rev92 named,
committed one layer down.** It is not the conservative choice either: the verdict withheld was EARNED, and the closure
forbids placing an unknown value IN `ℐ` — it does not license emptying `ℐ` of what is known. The key-log branch is NOT
symmetric and must not be swept with it: an unreadable key log erases a retirement, which lands on the identity carrier
itself. The coordinate is therefore three-valued at the boundary — a value, a determinate none (`404`/`410`), and
UNKNOWN — and the third is reported POSITIVELY, never as silence and never as `null`, which already denotes the
publisher's declaration that no grid exists.
(*"#169/F.4 an UNREADABLE cadence lands on the RANGE only — identity still resolves and the coordinate is reported unknown (disjoint carriers, rev92 one layer down)"*)

**Realization (rev85 — domain totality).** a frame is measurable with respect to its own anchored interval: adaptedness is refused when the covering interval is not chain-consistent — *"#39 chain-consistent covering interval ⇒ no-deletion-only (omission still possible)"*

## F.5 Verification is a measurability test — and the tiers are nested σ-algebras

This is the load-bearing section — restated in the category-correct form (16th-round rigor pass): a verifier
does NOT observe a random variable; it receives a CONCRETE document `d ∈ DocSpace` — data, not chance. What IS
uncertain is the WORLD around `d`: which genesis the name really serves, what witnesses saw, what the journal
contains. So tier validity is a **parameterized predicate**: for each fixed `d`,

  `Valid_τ(d) : Ω → {true, false}`,

and the tier σ-algebras are generated by the WORLD-coordinates (F.1) that the tier consults — never by the
document's own bytes (bytes are data; σ-algebras live on Ω):

- **𝒮_LIGHT(d) := {∅, Ω}** — the TRIVIAL σ-algebra. `Valid_LIGHT(d)` is CONSTANT in `ω`: a total deterministic
  function of `d`'s bytes alone (§14 floor). Constancy w.r.t. the trivial algebra is the STRONGEST possible
  measurability statement — this IS self-containment, said exactly.
- **𝒮_HIGH(d) := σ( W_n )** for the name `n` that `d` claims — the name-authority coordinate (F.1): the world
  facts that bind the name to a key (genesis, key-log, witness no-fork; §12).
- **𝒮_TOP(d) := σ( W_n ) ∨ Fₜ** — the join with the filtration at the anchor time: the journal coordinate makes
  "committed by real time `t`" a world-event. (A reorg-prone substrate enters `Fₜ` only at its registered
  finality, §11.2/§17 — nothing enters that the substrate may still roll back.)

By construction, for every fixed `d`:

  **𝒮_LIGHT(d) ⊆ 𝒮_HIGH(d) ⊆ 𝒮_TOP(d).**

(The alternative modeling — the document itself as a random variable `D : Ω → DocSpace` with
`σ(D) ⊆ σ(D,W) ⊆ σ(D,W,L)` — is equivalent for every theorem below and models PUBLISHER behavior; we fix `d`
because UST's verdict must be a function of the received bytes and the world's authority/journal coordinates,
never of the distribution documents are drawn from. Everywhere below, `d` is a fixed received document and
`Validτ` abbreviates `Validτ(d)`.)

Let a verifier's **information set** be a σ-algebra `ℐ` (what it can actually access: always the document; maybe a
reachable genesis/witness; maybe a reachable substrate). Let `Validτ : Ω → {true, false}` be the tier-`τ` validity
predicate; MEASURABILITY here always means the strict pre-image form: **the event `{ω ∈ Ω : Validτ(ω) = true}`
belongs to `𝒮_τ`** (equivalently, `Validτ` is measurable w.r.t. `𝒮_τ` and the discrete σ-algebra on `{true,
false}` — stated in pre-image form because any map into a two-point space is trivially "measurable" if the
domain algebra is rich enough; the CONTENT is which algebra contains the truth-event).
predicate.

**Theorem F.5 (Tier = measurability level).**
1. **(Self-containment of the floor.)** `Valid_LIGHT` is `𝒮_LIGHT`-measurable: it is a deterministic function of
   the document bytes alone (recompute canon + per-partition + `content_hash`; strict-Ed25519-verify the
   signature). Hence `𝒮_LIGHT ⊆ ℐ` **always** — the floor is decidable offline by anyone.
2. **(Each tier strictly refines with external information.)** `Valid_HIGH` is `𝒮_HIGH`-measurable but not in
   general `𝒮_LIGHT`-measurable — deciding it requires `𝒩` (name authority). `Valid_TOP` is `𝒮_TOP`-measurable
   but not in general `𝒮_HIGH`-measurable — it requires `Fₜ` (the anchor).
3. **(A verdict carries the finest decidable tier.)** The reported verdict is `VALID:τ` where `τ` is the finest
   tier with `𝒮_τ ⊆ ℐ` and `Validτ = true`. A bare `VALID` is never emitted (a verdict without its σ-algebra is
   meaningless).
4. **(Invariant I4 as totality + determinism.)** `Validτ` is defined by §14 as a TOTAL, DETERMINISTIC function
   of its `𝒮_τ`-measurable inputs — total because the §14a obligations table leaves no member present-but-
   unchecked and no input outside the table's domain, deterministic because every obligation is a recomputation
   with one right answer. Two verifiers given the same `𝒮_τ` inputs therefore compute the same value — not by
   assumption but because they evaluate the same total function. (This is not circular: the CONTENT of the claim
   is the totality and determinism of §14/§14a; a verifier that secretly consults information outside `𝒮_τ`, or
   skips an obligation, is non-conforming — the theorem is exactly what conformance testing checks.)
   **Realization (rev94 — a rule that no library performs is not enforced by delegating it, #144).**
   §7/N6 states one acceptance rule: reject `S ≥ L`, reject small-order or non-canonical `A`/`R`, verify
   cofactorlessly. This implementation performed NONE of the four itself; each answer came from whichever library
   the build's faculty wrapped.
   *A first version of this note argued that the danger was DIVERGENCE — that a borrowed rule makes the verdict a
   function of the platform, because Ed25519 implementations are known to disagree. That argument is kept here
   and marked WRONG, because measurement refuted it and the refutation is the useful part:* the reference
   edge-case corpus (Chalkias et al., 12 vectors) was run against three implementations — node:crypto, WebCrypto
   and Go's `crypto/ed25519`, the last an independent codebase rather than a second API over one library — and
   **all three agreed on all twelve**, cofactorless in each case. The predicted split did not appear.
   What the same measurement DID show is worse and quieter: **all three ACCEPT small-order `A`/`R` and one
   non-canonical `A`** — the cases §7/N6 says to reject. So the requirement was not being enforced weakly or
   inconsistently; it was not being enforced at all, by anyone, and could not have been noticed by comparing
   implementations to each other, because they are unanimous. Clause 4 is about two verifiers computing the same
   value; it says nothing about that value being the one the spec demands. **A rule delegated to a component that
   does not implement it is a rule with no realization — and a conformance suite that only compares the
   implementations against each other will never say so.** Both rejections are decidable from the wire bytes (a
   finite eight-element set of encodings; `y < p` plus the negative-zero case), which is why they now sit in the
   verifier rather than in a cryptographic routine, and why the corpus that exposed them is now part of the suite.
   **Corollary (the anti-monoculture argument is a statement about a CARDINALITY, #34).** Clause 4 says two
   verifiers given the same inputs compute the same value; the practical use made of it — differential testing,
   "a bug in one implementation cannot detect itself" — needs the number of INDEPENDENT implementations to be at
   least two. That number is a fact about the world, not about the text: with one implementation the differential
   argument is empty however carefully it is phrased, and a document asserting a second one that does not exist
   inflates the cardinality the whole argument rests on. Measured 2026-08-09: this repository claimed a Go binary
   in four places and contains zero Go files. The same shape as the paragraph above — a claim whose realization is
   absent — one level up: there the rule had no implementer, here the implementer has no existence. CLOSED 2026-08-09 for the WORDING (every mention is planned-tense and a gate holds it there); OPEN for the substance — #34 is what would make a second implementation exist, and until it does this project has one.
   **Realization (rev93 — an ASYNCHRONOUS surface does not weaken I4; it changes how I4 is observed, #144).**
   `Validτ` is a function of bytes, and awaiting does not make it a function of anything else — the predicate is
   untouched. What changes is the shape of the two properties in a realization, in two ways that are not
   symmetric. **Totality becomes SETTLING, not returning:** a rejected promise is a second way to fail to be
   total, and it is worse than a throw because it is invisible to a caller's `try`/`catch` when the `await` is
   forgotten. This obligation already exists and is enumerated over the RUNTIME namespace rather than a source
   list (*"R47 P1-03 (roster completeness — RUNTIME namespace) — EVERY function-typed export of the module (100,
   incl. re-exports + arrow-consts + the byte kernel checkAuthorityProofBytes) is TOTAL on a hostile Proxy UNLESS
   explicitly classified MAY-THROW"*), so widening the async surface widens the obligation automatically rather
   than requiring a new rule — a newly-async export is covered the moment it exists. **Determinism becomes a claim about the WINDOW:** between two suspension points a live
   input can be substituted, and the predicate would no longer be a function of the bytes it was called on. The
   obligation exists (snapshot before the await), but it was written around the ONE suspension point a substrate
   check introduced; an asynchronous cryptographic faculty creates as many suspension points as there are
   signatures in the walk. The count is therefore not an implementation detail: **it is the size of the window in
   which the predicate can stop being a function of its own input**, and freezing the input at the public door
   before the first suspension is what keeps the window empty.
   **Corollary (the window is REMOVABLE, not merely guardable).** Keeping a window empty is a discipline, and a
   discipline is a thing one can forget. It can instead be made non-existent: an asynchronous surface admitted
   over IMMUTABLE BYTE-STRINGS has no window at all, because there is no live object to substitute and no caller
   code runs on the path — the argument is copied into a fresh buffer before it is parsed, so the count of
   suspension points becomes irrelevant rather than bounded. This is STRICTLY STRONGER than the synchronous
   object path, which is sound only while its snapshot discipline is remembered; the byte boundary is sound
   because nothing else is reachable. The same asymmetry was measured once already, when an indexed getter in one
   argument mutated a sibling's not-yet-captured bytes and flipped a verdict — the fix was not a more careful
   read but a domain the caller cannot participate in. Asynchrony is therefore an OCCASION to close the class:
   the property "every asynchronous entry takes bytes" is structural and can be enumerated over the runtime
   namespace exactly as totality is, so an object-shaped asynchronous entry cannot be introduced by accident.
   **Realization (rev24 — totality includes malformed non-null on EVERY argument, not just null config):** the public
   boundary returns a structured verdict for a null/hostile TRAILING argument, not only a null config record — the
   round-24 grid was extended past `arg1`/`null-only` (*"round-26 L5 malformed non-null on trailing args: resolveCadence and verifyJson accept a null trailing arg and return structured (no host throw)"*).
5. **(INDETERMINATE as a missing σ-algebra — or a declined evaluation.)** If `𝒮_τ(d) ⊄ ℐ` (e.g. the witness is
   unreachable, so the name-authority coordinate `W_n ⊄ ℐ`), then `ℐ` is **in general insufficient** to decide
   `Valid_τ(d)` — there is NO general decision procedure at tier `τ`. (For a PARTICULAR `d` the predicate may
   degenerate to a constant — e.g. a malformed `d` makes `Valid_HIGH(d) ≡ false`, decidable even under `{∅,Ω}`;
   missing information forecloses the general procedure, not necessarily every instance.) The same
   outcome also covers a verifier that HOLDS the inputs but does not evaluate the function (an optional
   algorithm it does not implement, a resource budget): formally the information is present and the verifier
   declines to compute — the honest report is still `INDETERMINATE(reason)`, never a guessed verdict. Distinct
   from `INVALID` in both cases.
   **Realization (rev92 — the refusal must survive every consumer, not just the one that raises it).** Measured
   2026-08-09 (#144): the clause above was already normative and the code contradicted it, because a refusal is
   raised at a leaf and READ many layers away. Two shapes destroyed it in transit. A leaf whose codomain is
   two-valued has nowhere to put the third outcome, so a `catch` that was written for malformed input silently
   converted "I cannot check" into `false`; and a boundary that maps every exception to a refusal is right about
   a defect in the DOCUMENT and wrong about a defect in its own faculty. The corollary is stronger than either
   fix: **an inability that is not carried as a typed condition through EVERY consumer of a verdict becomes a
   verdict.** Enumeration is therefore part of the obligation — of sixteen consumers, seven turned inability into
   an accusation and one, testing only for an error field that `INDETERMINATE` does not carry, turned it into a
   silent confirmation, which is the worse direction: an accusation is visible to a careful reader, a
   confirmation is what a forgery would want. Authority is **denied, never forged**
   (`W1`): an adversary who suppresses the witness removes `𝒩` from *everyone's* `ℐ`, which can only *lower* a
   tier, never fabricate one.

*Sketch.* (1) canon/hash/verify are total deterministic functions of the FIXED received document `d`'s bytes;
`Valid_LIGHT(d)` is therefore constant in `ω`, i.e. `{∅,Ω}`-measurable — the strongest measurability.
(The determinism premise is NORMATIVELY guaranteed, not assumed: §6 pins RFC 8785 JCS with tightenings, §5's
string-only value model makes float/NaN edge cases UNREPRESENTABLE by construction, and the raw-bytes boundary
(§S6/F7 `verifyJson`) rejects duplicate keys before any parser ambiguity can arise — a parser that "floats" on
edge cases is non-conforming, so the total-determinism claim is exactly what §16 conformance vectors test.)
(2) name authority and anchoring are, by §12/§11, facts about objects **not contained in `R`**; the verdict genuinely
depends on them, so it is measurable only in the larger σ-algebra. (3)–(5) are then read off the containment
`𝒮_LIGHT ⊆ 𝒮_HIGH ⊆ 𝒮_TOP` and the definition of `ℐ`. ∎

**Reading of the theorem.** *"Verify" is not "is this true" — it is "with respect to which σ-algebra is this
record measurable, and is it measurable-true there."* The tier ladder is literally a tower of nested information
σ-algebras; climbing it means bringing more (external, harder-won) information into `ℐ`. `VALID:LIGHT/HIGH/TOP`
is the honest name of *how much information the verdict rests on*.

## F.5.0 Assurance is a PRODUCT LATTICE; the tier is one policy projection (#78, gaps 1–3)

The nested tower `𝒮_LIGHT ⊆ 𝒮_HIGH ⊆ 𝒮_TOP` above is ONE cut through a richer object. The audit (#76) separated
structure the linear tier had fused, so F.5 is restated in product form — the per-mechanism theorems `F.5a–F.5n`
below are its per-AXIS realizations (this subsumes the `F.5a–F.5f` sketch of #78: those names were taken by the
built theorems during #76, so the framework moves here and the letters stay per-axis).

**M1.1 (rc.36) — STRENGTH is separate from SUPPORT.** The rc.35 statement was self-contradictory: EvidenceBasis was
DEFINED as "a SET of capabilities" yet the theorem asserted "every axis is a total order" and counted `2·4·4·2·4 =
256` — a capability set is a Boolean lattice `(P(Caps), ⊆)`, not a 4-element chain (and the realized code axis was a
4-chain the live verifier pinned to `opaque` — a phantom coordinate). The corrected structure:

```
Strength          := Integrity × IdentityStrength × FreshnessStrength × TimeStrength     (2·3·4·2 = 48, each a CHAIN — identity is 3 rungs since round-53 dropped `pinned`)
CapabilitySupport := (P(Caps), ⊆)                                                        (a finite Boolean lattice)
AssuranceReport   := { strength ∈ Strength, support ∈ P(Caps), basis }
```

Verification measures FOUR orthogonal STRENGTH coordinates, each its own information sub-σ-algebra of `ℐ`:

- **Integrity** `𝒮_I(d) := {∅, Ω}` — the trivial algebra; the §14 floor, a total function of `d`'s bytes.
- **IdentityStrength** `A_id := σ(name-binding, active-genesis uniqueness)` (§12.1a / F.5a, F.5j).
- **FreshnessStrength** `A_fresh := σ(terminality, chain-consistency, temporal order, checkpoint uniqueness)`
  (§12.2a/§12.3 / F.5i, F.5n).
- **TimeStrength** `Fₜ` — the anchor filtration (§11.2 / F.5c).

**CapabilitySupport** — which capabilities the ADMITTED evidence supplies — is deliberately NOT a fifth strength
coordinate: `Caps = {order, time, inclusion, consistency, membership, non-membership, content-equality,
availability}` (single-sourced from `EVIDENCE_CAPS` via `EVIDENCE_CAPS_UNIVERSE`, `|Caps| = 8`, so `|P(Caps)| =
256`), partially ordered by SET INCLUSION — capabilities are NOT naturally linear (map-uniqueness,
transparency-consistency, content-equality and trusted-timestamp are mutually incomparable — *"M1.1 support is ⊆-ordered, not a chain"*; the universe is pinned by *"M1.1 EVIDENCE_CAPS_UNIVERSE"*). **Support DERIVES strength; it
never IS strength:** a predicate is discharged only by an admissible capability — temporal order needs
`order`/`time`, so a proof-kind bearing neither (`content-addressed`, `authenticated-map`, opaque) enters `Fₜ`
under NO circumstance (Variant A, F.5g) — and the seam (F.5g) guarantees no caller mints support (B3/B4).

**Realization (rev93 — a report NAMES what it measured and OMITS what it could not, and the two are not
interchangeable).** rev92 established that a report may be strictly wider than what it scores. This fixes the
remaining freedom: what a report is allowed to put in a slot it could not fill. There are exactly two honest
markers, and the choice between them is not stylistic — it is the difference between two facts a consumer must
be able to tell apart:

- a NAMED floor value means **the measurement ran and earned nothing** — `Π(⊥) = NONE` is exactly this, and it
  is why `NONE` was given a name rather than left as an absent field;
- ABSENCE means **the measurement could not run** — the tier field is absent under `INDETERMINATE`, whose
  assurance is PARTIAL rather than `⊥`, so ranking it `NONE` would under-claim as badly as an over-claim.

Collapsing the two loses a distinction the theory is built on: availability is not failure. And absence is the
weaker marker for a reason that has nothing to do with meaning — it is **indistinguishable from a coordinate a
reader's implementation never had**. A consumer reading a missing field cannot tell "could not be measured" from
"this verifier predates the field", so absence carries information only when a NAMED sibling in the same report
already carries it. `INDETERMINATE` is that sibling for the tier; an availability status is that sibling for a
basis. Where no such sibling exists, a report MUST name.

The failure this forbids is a THIRD option that is neither: inventing a value to fill the slot. A word minted for
an empty slot is unfalsifiable by construction — nothing in the model can contradict it, because it denotes
nothing in the model — and it is read by a consuming agent as a measurement that happened. That is strictly worse
than either honest marker, since both of those are recoverable and a fabricated rung is not: it says less than
`NONE` and claims more than absence.

**The third case: a slot that is FILLED with a value the derivation refused to count.** The pair above ranges over
EMPTY slots. There is a case neither marker covers, and it is the one that actually shipped: a value that was
obtained, is not invented, denotes something real — and earns nothing. C3 already fixes its arithmetic: strength
coordinates are derived from SEAM VERDICTS by fixed rules, and *"C3 a bare strength LABEL without a verified status earns nothing (no caller labels)"*, so `{strength: authoritative}` with no `verified` status yields `self-asserted`, exactly as
`{strength: corroborated, status: unavailable}` does. The seam label is INERT — the derivation neutralizes it.

That neutralization is a statement about the transition, not about the report. It protects the TIER; on its own it
does not protect the READER. A verdict that carries the earned coordinate AND the inert seam label side by side
hands a consumer two answers to one question, of which only one was adjudicated — and a consuming agent reads
fields in isolation, so it will read whichever it reaches first. The label the derivation discarded is then a
stronger claim than the coordinate the derivation earned, published beside it under the same word.

So the discipline extends across the report boundary: **a value the derivation neutralizes MUST NOT be surfaced
under a name that reads as a result.** The remedy is the FIRST case above, not the second: report the NAMED FLOOR
the axis already has. Absence is wrong here and the reason is exact — the slot is not empty. The measurement ran
far enough to earn the floor, the floor has a name (`self-asserted`), and a strength must be shown WITH its status,
so removing the strength would leave a status qualifying nothing. Omission was this note's first prescription and
it was wrong: it read the case as an empty slot because the value in it was worthless, which confuses "earned
nothing" with "measured nothing".

One asymmetry is deliberate and must not be flattened. A seam label is not always inert: where a consumer's own
opt-in lifts it, the report keeps the SEAM label (`consumer-override`) beside an earned coordinate that reads
`authoritative` — and that difference IS the provenance, the one signal telling a consumer the authority rests on
its own assertion. Collapsing the report onto the earned coordinate would erase exactly the fact a consumer most
needs. So the rule is about the neutralized case only, and its remedy is the floor.

**Realization (rev95 — a ceremony's self-check asserts what the ceremony PRESERVES, never a property of the world).**
A ceremony operates on the inputs it holds: a cold key, a fetched log, a declared parameter. Its self-check exists
for one purpose — to refuse to emit something broken — so the property it tests must be one the ceremony itself
determines. A check that asks instead about the WORLD (is this name authoritative, did a witness confirm, is the
network reachable) depends on evidence the ceremony neither has nor should have, and there are only two outcomes:
it fails always, or it passes vacuously. Both are worse than no check, because both read as one.

The generative form is: for each ceremony, name the invariant it must preserve, and test THAT.
  · genesis — the documents it emits VERIFY (the floor, a function of the bytes it just produced)
  · cadence — the grown log RESOLVES to the declared grid at the declared moment (F.4)
  · rotation — the new key is in the ACTIVE SET after the grown log: F.5e fixes exactly this, `rotate` signed by
    `s` naming successor `k` ⇒ `active ∪ {k} ∖ {s}`, with the admissibility invariant `signer(e_{i+1}) ∈ active(after e_i)`

Measured on 2026-07-27: rotation asked `resolveAuthority(...).strength === 'authoritative'` while supplying only
`noForkConfirmed`, which yields `consumer-override` — a value #98 had that same day HARDENED the protocol to
withhold, precisely so a caller's boolean cannot name a canonical. So the ceremony demanded of a flag a property
the protocol had just decided that flag may not confer, and `ust rotate` died on its own check every time. It is
the only recovery from key compromise.

The other two ceremonies asked correctly, and that was LUCK rather than discipline — nothing stated the rule, and
nothing stopped a fourth ceremony from copying the wrong one. An invariant that lives only in how three cases
happen to be written is not an invariant; this note plus its gate is what makes it one.

**Realization (rev94 — a DECISION procedure must agree with the projection, and neither report field alone does).**
Fork choice asks one question of a candidate: is its key BOUND to the name it claims. The model already answers what
name-binding is — the derived identity coordinate reaching `corroborated` or above — so a procedure that decides
bindingness is correct exactly when it agrees with that coordinate. That is a testable equivalence, not a matter of
which field is convenient.

Measured over the seam grid, the two obvious readings BOTH fail, for opposite reasons:

- reading the DERIVED coordinate is a LOOSENING. `π_override` rewrites a `consumer-override` seam to
  `authoritative` before derivation when the consumer opts in, so the derived coordinate is precisely the object
  that can carry a rung a caller BOOLEAN minted. A fork is then adjudicated by the assertion of the party asking.
- reading the SEAM label disagrees with the coordinate in 6 of 10 seam states — every state where C3 neutralizes the
  label (`suspect`, `unavailable`, `expired`, `premature`) still reads as binding.

So the decision is not a projection of either field; it is the CONJUNCTION of the two facts the model separates:
`strength ∈ {corroborated, authoritative} ∧ status = verified`. The first conjunct excludes the consumer lift —
the report deliberately KEEPS the seam label `consumer-override` beside the lifted coordinate, and that retention is
what makes the exclusion expressible at all. The second reproduces C3's neutralization. Together they equal
`derived identity ≥ corroborated ∧ ¬consumer-lifted`, with zero disagreements across the grid.

Why this had to be stated rather than left to the code: the seam-only reading was OBSERVATIONALLY sound, because a
neutralized label floors the tier to LIGHT and §14 turns a name-form LIGHT document into INDETERMINATE, which fork
choice filters before its predicate. But §14 EXEMPTS `genesis`/`key`/`cadence` — those stay VALID:LIGHT and do
reach the predicate. So the guard was standing two functions away, in a filter whose exemption list is a separate
decision. A decision procedure whose correctness depends on a reachability accident elsewhere is not proved; it is
merely not yet wrong.

**Gap 3 — split `A_id` from `A_fresh`.** These were the two facts `𝒮_HIGH`'s `W_n` fused; F.5a already splits
name-binding from no-fork, and here the split is axis-level: name authority and key-log freshness are measurable
one WITHOUT the other.

Each strength axis is a finite TOTAL order of earned strengths (a rank): *"LATTICE (1) every axis is a total order"*. The **AssuranceState** of `d` is the tuple `A(d) = (I, IdentityStrength, FreshnessStrength, TimeStrength)
∈ 𝓐 := ∏ axes`, ordered COMPONENTWISE (`A ≤ A'` iff `≤` on every axis). `(𝓐, ≤)` is a finite distributive LATTICE —
meet = per-axis min, join = per-axis max — a reflexive/antisymmetric partial order
(*"LATTICE (2) product order reflexive + antisymmetric"*) obeying the lattice laws over the full
*"LATTICE product = 48 states"* (*"LATTICE (3) meet=glb, join=lub, commutative + absorption"*).

**Gap 1 — independence WITHOUT `⊥` (M1.4).** The symbol `⊥` was overloaded (bottom / orthogonality / probabilistic
independence / contradiction — and the model carries no probability measure). The honest statement is PRODUCT
INCOMPARABILITY: `(id₂, fresh₁)` and `(id₁, fresh₂)` are incomparable in `(𝓐, ≤)` whenever `id₂ > id₁` and
`fresh₂ > fresh₁` — identity and freshness strengthen on independent coordinates, so neither dominates —
*"LATTICE (4) A_id"* / `A_fresh` product-incomparability. The linear tower collapsed this; the product keeps them
apart.

**M1.2 — Reachability: laws on the ambient product, security on the image.** The 48-state product contains states no
honest derivation emits (e.g. `Time = anchored ∧ Freshness = unverified` where the anchor IS fresh evidence). Define
`Reach_C := image(deriveAssurance_C) ⊆ Strength` — the tuples the verifier can actually output under consumer config
`C`. Lattice LAWS (meet/join/monotone `Π`) are proved on the ambient product (above); SECURITY properties
(no-upward-forge, downgrade-resistance, no-rung-without-its-predicate) are stated on `Reach_C` — the
evidence→assurance transition where the rc.35 findings lived; the exhaustive 48-state checks exercise the rank
ALGEBRA, not that transition. The confinement property (`deriveAssurance_C` never leaves `Reach_C`) is REALIZED as a running sweep:
*"V1 Reach_C confinement: 240-combination verdict grid — every coordinate earned by its own predicate, tier = projection"*
and *"V1 Reach_C per-coordinate locality: a coordinate is a function of ITS verdict alone (no cross-coordinate lift)"*.
The C3 seam is realized: `provePredicates({identity, freshness, anchor, evidence})` — the UNBRANDED pure mapper (round-25 P0-01) whose graph `deriveAssurance` projects
— pure/total/frozen, strength coordinates derived from SEAM VERDICTS by fixed rules (a bare label or a caller boolean
earns nothing: *"C3 a bare strength LABEL without a verified status earns nothing (no caller labels)"*,
*"C3 freshness rung only from a VALID freshness verdict, never a label"*, *"C3 anchored time requires inclusion === true AND time === anchored from the anchor seam"*), support = capabilities of
`image(VerifyEvidence_C)` members only (*"C3 support: only image(VerifyEvidence_C) contributes capabilities — a minted look-alike contributes none (B3)"*), and §14 `verify()` assembles through THIS one function (the consumer-override
π_override projection applied explicitly BEFORE assembly). **K3:** `deriveAssurance` takes ONLY a branded `PredicateGraph` handle, minted ONLY by `verify()`'s module-private seal over VERIFIED seam verdicts — the exported `provePredicates` is the UNBRANDED pure mapper, so a public caller cannot mint the brand (round-25 P0-01 closed the forgery oracle: minting the brand from caller labels let `deriveAssurance` bless TOP with zero verified evidence). A caller-shaped `{identity:'authoritative'}` is not a branded graph, so no coordinate lifts — round-3 P0-4 closed at the type level (*"K3 deriveAssurance REJECTS a caller-shaped object (not a PredicateGraph) → E-ASSURANCE (round-3 P0-4 closed)"*, *"K3 provePredicates is UNBRANDED — a caller cannot mint a graph the assembler will bless (round-25 P0-01: the forgery oracle is closed)"*).

**M1.3 — strict rungs via INFORMATION ALGEBRAS, not σ(verdict).** Every ladder in this model is defined over the
σ-algebra generated by the OBSERVABLES a verifier admits — never over verdict outcomes (for Boolean predicates
`Y ⇒ X` does not order `σ(X), σ(Y)`). The freshness ladder: `ℐ_unverified := {∅, Ω}`;
`ℐ_fresh := ℐ_unverified ∨ σ(fresh-fetch: as_of ≥ anchor)`; `ℐ_corrob := ℐ_fresh ∨ σ(authorized-chain,
head∈committed-root, terminal, chain-consistent, proven-after)`; `ℐ_attested := ℐ_corrob ∨ σ(independent
anti-equivocation: distinct-domain quorum ∨ authenticated-map uniqueness)`. Each inclusion is STRICT exactly under
the non-degeneracy hypothesis below — the P0 fixes (consumer-rooted §B2, capability-checked F.5g) ENFORCE it. The
identity ladder `ℐ_self ⊊ ℐ_corrob-id ⊊ ℐ_auth` has the same shape (F.5a).

**Non-degeneracy (P2-01) — the STRICT inclusions need a NAMED hypothesis.** Claims like `corroborated ⊊ authoritative`
(F.5a) and `corroborated ⊊ attested` (F.5j) are STRICT only under an explicit assumption, made here: the independent
coordinate (the authenticated map root, or the accepted-witness quorum) is NOT a measurable function of the
publisher's own view, AND there exist histories `ω, ω'` agreeing on the publisher view but differing in that
coordinate (a rival genesis, or a rival checkpoint at the same coordinate). In a DEGENERATE model — the map is a
function of the publisher's list, or no rival history exists — the σ-algebras coincide and the "inclusion" is
EQUALITY, not strict. The audit is the operational face of this: the P0 fixes make the independent coordinate
CONSUMER-rooted (§12.3.4) and capability-checked (§12.3.5), so it is genuinely not publisher-controlled — the
hypothesis is not merely assumed but ENFORCED (a self-supplied root no longer reaches the strong rung).

**Per-edge predicates (P2-03) — each adjacent rung is strictly stronger by a CHECKED predicate, not a declared rank.**
The lattice laws hold for ANY rank order; they do not prove that a rung EARNS its place. Each edge is a theorem with a
running realization (the P0-01..05 reproductions, now `security-regression.mjs`, are precisely the attempts to reach a
rung WITHOUT its predicate — all rejected):
- `corroborated ≺ authoritative` (identity): INDEPENDENT active-genesis uniqueness under a consumer-rooted map (F.5j/F.5k) — enforced by the trust boundary (§12.3.4) and *"LATTICE (4) A_id"* independence.
- `fresh ≺ corroborated` (freshness): an authorized checkpoint chain ∧ strict SIZE-BOUND terminality (F.5n) ∧ proven-after ordering of a CAPABILITY-typed commitment (F.5g).
- `corroborated ≺ attested` (freshness): + INDEPENDENT anti-equivocation (F.5j); the top rung is unreachable without it.
- the projection over these axes agrees with the realized verifier — *"LATTICE (6) projectTier agrees with the realized"* tier — so the ranks are not free declarations but the live machine's own order.

**Theorem F.5.0 (Tier is a monotone policy projection).** The classic tier is a map `Π : 𝓐 → {NONE ≺ LIGHT ≺ HIGH
≺ TOP}` reading ONLY the Integrity, IdentityStrength and TimeStrength coordinates: `Π(A) = TOP` iff
`IdentityStrength = authoritative ∧ TimeStrength = anchored`; `HIGH` iff name-bound (`IdentityStrength ≥
corroborated`); `LIGHT` iff the integrity floor holds; `NONE` below it (*"LATTICE (6b) integrity floor unmet"*).
`Π` is ORDER-PRESERVING — `A ≤ A' ⇒ Π(A) ≤ Π(A')`, so more assurance NEVER lowers the tier:
*"LATTICE (5) projectTier is monotone"*. And `Π` agrees with the §14 verifier on every realized strength — no
second truth: *"LATTICE (6) projectTier agrees with the realized"* tier. Crucially `FreshnessStrength` (and the separate
`CapabilitySupport` lattice) are NOT in `Π`'s image: they strengthen the report WITHOUT moving the linear tier —
the product carries assurance the scalar ladder cannot express.

**Gap 2 — `ℐ_C`, the CAPPED term.** A consumer config `C = (accepted roots, accepted issuers, issuer→trust_domain,
installed-verifier trust, policy floors)` induces `ℐ_C = σ(evidence verified AND admitted under C) ⊆ ℐ`. The
REPORTED assurance is the MEET of what is proven and what is admissible under `C`: `A_C(d) = A(d) ∧ ceil(C)`.
Assurance is thus EARNED by proof and CAPPED by trust — `C` can only LOWER it: `A_C ≤ A` on every axis, idempotent
(*"LATTICE (7a) capAssurance downgrade-only"*), and no ceiling ⇒ identity (*"LATTICE (7b) no ceiling"*). A
publisher who PROVES TOP is still read as LIGHT by a consumer that admits no trust roots and no independent
domains: *"LATTICE (7c) proven-TOP capped by no-trust-roots"*. A missing/out-of-range axis is never guessed —
*"LATTICE (8) missing/out-of-range axis"* ⇒ fail-closed. This is the measure-theoretic content of "assurance is
never self-declared": `ℐ_C` is the consumer's, and the meet is computed, never asserted by the publisher.

*Sketch.* Each strength axis order is total and finite, so `∏` under the componentwise order is a finite
distributive lattice with per-coordinate meet/join (standard); the three properties are checked exhaustively over
all `2·3·4·2 = 48` states and `48²` pairs. `Π` is monotone because each of its three read coordinates is monotone and the
`TOP/HIGH/LIGHT` thresholds are up-sets; agreement with §14 is the `identity×time` case check. `ceil(C)` is an
element of `𝓐`, so `A ∧ ceil(C) ≤ A` is immediate from meet, giving downgrade-resistance (F.5b) as a lattice fact,
not a separate axiom. ∎

**Reading.** The ladder `LIGHT/HIGH/TOP` is the shadow `Π` casts from the product lattice onto one policy axis;
identity, freshness, time and evidence are the real, independently-earned coordinates, and `ℐ_C` is the consumer's
trust ceiling meeting them. Assurance is a POINT in a lattice — capped by trust, projected to a tier — never a
scalar, never self-declared.

## F.5a No-fork is authenticated non-membership — `corroborated ⊊ authoritative`

The name-authority coordinate `W_n` of `𝒮_HIGH` bundles TWO different facts, and honesty requires splitting
them. Resolving the key — genesis self-signed, key-log `prev`-chained, `key_id ∈` the resolved set (§12.2) —
binds the presented key to the name; call this event `K_n`. The **no-fork** requirement of §12.1 is a SECOND,
strictly harder fact: that no RIVAL name-binding root is active for `n`. By Corollary F.3.1 this is an
**authenticated non-membership** statement, `¬∃ B ≠ A : B ∈ activeGenesis(n)`, and — exactly as for backdating on
the time axis — it does NOT follow from any collection of positive membership facts. A witness endpoint that
serves the publisher's OWN list of bindings proves only `A ∈ served-list` (membership); the publisher can OMIT a
rival it does not wish seen, so the served list is not in the σ-algebra that decides non-membership. Two
distinct predicates result:

- **`corroborated(n)`** — `K_n` holds AND the served witness list shows exactly one active anchored binding,
  equal to the resolved one. Decidable in `σ(K_n, served-list)`; it is the existence fact `A ∈ published-set`.
- **`no-fork(n)` (= `authoritative`)** — `K_n` holds AND an INDEPENDENT, anchored authority over `n`'s bindings
  excludes every rival. The economical witness of the exclusion is a **verifiable map keyed by the name**: an
  authenticated dictionary `n ↦ activeGenesis(n)` (a Merkle prefix tree / key-transparency structure) whose
  signed root is itself committed to the anchor substrate, so the root enters `Fₜ` (§11/F.3). PREFIX-UNIQUENESS
  is the whole mechanism: a key has exactly one leaf, so an inclusion proof for key `n` returning `A` IS the
  non-membership proof for every `B ≠ A` at `n` — the universal `¬∃B` collapses to a single positive lookup.
  Consistency proofs between successive signed roots give append-only; a monitor watching the leaf at `n` gives
  detection (`W1`). Decidable in `σ(K_n) ∨ Fₜ`.

**Proposition F.5a (M1.3 form — σ of the EVIDENCE, never of the verdict).** Let `ℐ_corrob-id := σ(key-binding,
the publisher's served list)` and `ℐ_auth := ℐ_corrob-id ∨ σ(anchored map-coordinate / consumer-admitted witness)`.
Then `ℐ_corrob-id ⊊ ℐ_auth`, STRICT under the F.5.0 non-degeneracy hypothesis (the map/witness coordinate is not a
measurable function of the publisher's view, and two histories exist agreeing on the served list but differing at
the coordinate — a rival genesis). The rc.35 wording `σ(corroborated) ⊊ σ(no-fork)` was a category error: for
Boolean predicates `Y ⇒ X` does NOT order the OUTCOME σ-algebras `σ(X), σ(Y)` — the ladder lives on the observables
a verifier admits, not on verdicts. Corroboration is decidable from data the PUBLISHER serves; no-fork requires the
map coordinate, which the publisher does not control — the same separation as membership vs authenticated
non-membership in F.3.1, now on the NAME axis rather than the TIME axis. Consequently the honest
verdict when `ℐ` holds only the served list is **`corroborated`** — a real, bounded fact (key-bound name, no
rival in the publisher's own view), NOT nothing — and **`authoritative`/`no-fork`** is emitted only when `ℐ`
contains an anchored map-inclusion for `n`. Suppressing the map removes it from *everyone's* `ℐ`, which lowers
the verdict to `corroborated`, never forges `authoritative` (`W1`).

What this does NOT touch: neither predicate enters `𝒮_LIGHT` (the document bytes). The map is a WORLD-coordinate
whose root rides the SAME substrate `Fₜ` that TOP already trusts — no new root of trust — and the genesis,
key-log and state documents are unchanged in shape. No-fork is the identity twin of snapshot-complete
non-membership on the time axis: both are F.3.1 authenticated non-membership over a domain that UST's existing
structure already commits (the frame grid for completeness, the anchored name-map for no-fork). The strong word
is EARNED by bringing that non-membership coordinate into `ℐ`, not bought by weakening the definition.

**Realization (rev85 — domain totality).** authenticated non-membership is proven, never assumed: an absent key yields proven non-membership that stops short of authoritative — *"#42 SMT non-membership: absent key → proven non-membership (absent:true), not authoritative"*

## F.5a.1 Independence is CONSUMER-owned; the raw override is a distinct axiom (P0-2, REV 44)

F.5a gives ONE independent-authority witness (the anchored name-map, mechanism b). REV 44 adds a second — an
accepted external witness — and in doing so pins down WHAT makes an authority "independent". The answer is not a
property of the signed statement; it is a property of the CONSUMER.

**Consumer configuration.** Fix `C = (roots_C, dom_C)`: a partial map `roots_C : issuer_id ⇀ pub` (the witnesses
this consumer accepts) and `dom_C : issuer_id → trustDomain` (which independent domain each admitted issuer sits
in). The assurance-relevant information set is not the raw `ℐ` but a `C`-indexed sub-σ-algebra
`ℐ_C = σ( e : e is cryptographically verified ∧ e is admitted under C )`. This is the formal reading of CAPPED in
"earned, capped, quorum": bytes a consumer can fetch are not yet in `ℐ_C` — admission under `C` is required.

**Admitted no-fork evidence.** `e = (claim, issuer, sig)` is ADMITTED for target `(n, g)` under `C`, written
`Admit_C(e, n, g) = 1`, iff (1) `claim.purpose = "ust:name-no-fork"` ∧ `claim.domain_shard = n` ∧
`claim.active_genesis = g` (typed, domain- and epoch-bound); (2) `claim` declares no `trust_domain` and no
`issuer_id` of its own (independence is not self-granted); (3) `issuer ∈ dom(roots_C)` ∧
`EdVerify(roots_C[issuer], canon(claim), sig)` (consumer-accepted AND cryptographically valid).

**Theorem F.5a.1 (independence is earned from `C`, never self-declared).** `authoritative(n)` is measurable in
`ℐ_C` iff `K_n` holds and either (a) `∃ e : Admit_C(e, n, activeGenesis(n)) = 1`, or (b) an anchored name-map
coordinate for `n` (F.5a b). A witness's OWN `trust_domain`/`issuer_id` field never contributes: it is
producer-supplied, so it fails clause (2) and is excluded from `ℐ_C`. Hence no signed statement can raise its own
verdict — the "assurance is never self-declared" invariant, transposed onto the independence dimension.
*Proof.* Clause (3) conditions admission on `roots_C` and the signature, both outside the producer's control at
verification time (the consumer chooses `roots_C`; the key is fixed). The only producer-controlled independence
claim is a `trust_domain`/`issuer_id` INSIDE `claim`, which clause (2) discards. So the independence coordinate
enters `ℐ_C` only through `C` (or the map's `Fₜ` root, F.5a), never through `e`'s payload. ∎

**Consumer-override is a side axiom, not a rung.** A raw caller flag `noForkConfirmed` supplies no evidence: it is
a 0/1 axiom `Ax_C` the consumer adjoins to its OWN view at its own responsibility, yielding the DISTINCT strength
`consumer-override` with `independently_verified = ⊥`.

**Proposition F.5a.1 (the override never silently equals `authoritative`).** `consumer-override` is decided by
`Ax_C` alone, by no coordinate of `ℐ_C` (neither the served list of `corroborated` nor the admitted-witness/map of
`authoritative`). So on the identity axis the INFORMATION ladder stays `ℐ_self ⊊ ℐ_corrob-id ⊊ ℐ_auth` (M1.3 —
σ-algebras of admitted observables, not of verdicts), and `consumer-override` sits OFF this chain as a labelled
consumer axiom. It maps onto the
name-authoritative TIER only under an explicit projection `π_override` (`acceptConsumerOverride`), and the verdict
always carries `independently_verified = false`. In particular `noForkConfirmed = 1` alone never yields the label
`authoritative` — the REV 44 overclaim (a raw boolean earning `authoritative`) is closed by construction.

**Realization (round-237 — an axiom is a reason to CONCLUDE more, never a reason to OBSERVE less).** F.5a.1 settles what `Ax_C` is worth and says nothing about what asking it costs, so the implementation drew the missing inference the cheap way: `resolveByDiscovery` skipped the witness probe entirely whenever the caller had spoken (`callerNoFork = noForkEvidence !== undefined || noForkConfirmed`). Measured 2026-08-16 by counting the surfaces discovery actually fetches: with no assertion it reads genesis, cadence, keylog and **witness** and resolves `corroborated`; with `noForkConfirmed: true` it reads the first three, never the fourth, and resolves `consumer-override` — so adjoining a TRUE axiom LOWERED the tier, and the ordering inside `resolveAuthority` that would have preserved it never applied, because the observation it ranks was never made. The error is a confusion of two different relations to `ℐ`. Adjoining `Ax_C` enlarges the consumer's own view; it says nothing whatever about `σ(observables)`, which is fixed by what the verifier looked at. Declining to look SHRINKS that σ-algebra, and no axiom licenses that: `ℐ_self ⊊ ℐ_corrob-id ⊊ ℐ_auth` is an information ladder, and a claim cannot climb it or authorise skipping a rung. The consequence is not confined to the tier. **The fork test lives on the branch that was skipped**: `w.status = fork ⇒ E-GENESIS` is reachable only through the probe, and the served list is its only source, so a caller asserting *no fork* switched off the verifier's own search for a rival genesis — the precise condition the coordinate exists to detect, disabled by a claim about it. Hence the rule: the probe is suppressed by `offline` alone — an explicit statement that no request may leave — and never by anything a caller believes. **Both directions matter and neither is the other's mirror.** A caller axiom that AGREES with the served list costs nothing to keep: the served-list observation stands on its own footing and the axiom rides beside it as the labelled `consumer-override` it always was. A caller axiom that CONTRADICTS the probe is not a lattice operation at all — an information set holding both an observation and its negation is inconsistent, and a verdict drawn from an inconsistent set is worthless in the strict sense, so the answer is the refusal the probe already produces, not a reconciliation the verifier invents. **CLOSED** (2026-08-16, round 237): the probe runs whenever the transport is allowed to, and what a caller asserts changes only what is CONCLUDED from what was seen.


**Realization (extended REV 73 to the map authority).** The theorem is stated for a witness and holds verbatim
for the OTHER independent-authority witness of F.5a b: an entry in `mapAuthorities` carries the consumer's
`trust_domain`, the closed root-claim schema has no slot for one, and a statement carrying it is refused — so the
independence coordinate enters `ℐ_C` only through `C`. Two consequences are worth stating because they are easy
to fuse. First, ABSENCE of an assigned domain is UNESTABLISHED, never independent: inferring the strong reading
from silence would re-admit self-declaration through an omission instead of a field. Second, a publisher vouching
for itself through a map it operates is NON-EQUIVOCATING — an anchored root cannot say one thing to one consumer
and another to another (F.5a.3) — and that is a real property which is NOT independence. The two must be
distinguishable in the verdict from the first revision in which they can differ, or every verdict issued before
an independent authority exists is retroactively ambiguous. The consumer floor is `requireIndependentAuthority`,
and it reads whichever coordinate the route supplied, so both routes to `authoritative` answer the question the
same way.

**Realization.** `Admit_C` = `verifyNoForkEvidence(e, {domain_shard, active_genesis, trustRoots})`; the build side
is `buildNoForkEvidence`/`noForkClaim`. The earned/override split is the two terminal branches of
`resolveAuthority`: an admitted `e` → `{strength:"authoritative", basis:"accepted-external-witness", witness_id,
independently_verified:true}`; a raw flag → `{strength:"consumer-override", independently_verified:false}`. The
projection `π_override` is `acceptConsumerOverride` in `verify` (default off). (The general `ℐ_C` product-lattice
over all axes — identity × freshness × time — is the F.5 revision tracked in #78; F.5a.1 is its no-fork instance,
realized now.)

**Conformance (each claim is a running property — math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- Theorem F.5a.1(a): *"P0-2: verified noForkEvidence → authoritative + independently_verified + basis + witness_id"*.
- clause (2), self-declared domain excluded: *"P0-2: self-declared trust_domain inside the signed claim → rejected"*.
- clause (3), issuer ∉ `roots_C`: *"P0-2: witness NOT in the consumer trustRoots → not accepted"*.
- clause (1), typed epoch binding: *"P0-2: tampered no-fork claim ... → NOT authoritative"* and *"... not bound to this active genesis (cross-epoch replay) → NOT authoritative"*.
- Proposition F.5a.1: *"P0-2: raw noForkConfirmed → consumer-override (NOT authoritative), independently_verified:false"* and *"... raw noForkConfirmed alone on a name-form doc without binding → INDETERMINATE"*.
- `π_override` (tier only on opt-in): *"caller air-gap override (honored) → HIGH, the EARNED basis is kept and the axiom never becomes independent (#69 B / P0-2, round-237)"* and *"explicit --no-fork-confirmed (honored) still overrides ... → HIGH"*.

All green at REV 44 (conformance 228/0, cli 130/0, mcp live 11/0).

## F.5a.2 Uniqueness is proven UNDER a root; `active` is a claim about now — the currency step (#42)

F.5a discharges the universal negation `¬∃ B ≠ A : B ∈ activeGenesis(n)` by prefix-uniqueness: a key has exactly
one leaf, so one inclusion proof answers for every rival at once. That step is correct, and it is not the whole
distance to the verdict the ladder emits.

**Two statements, one implication between them.** Write `bind(n, R)` for the value at key `n` under signed root
`R`. An inclusion proof establishes

- `incl(n, A, R) ⇒ ¬∃ B ≠ A : bind(n, R) = B` — uniqueness **under `R`**.

`identity = authoritative` asserts `activeGenesis(n) = A`, evaluated at verification time `t`. Passing from the
first to the second requires `R = R_t` — that `R` is the CURRENT root of the authority. Call this predicate
`Cur(R, t) := ¬∃ R′ : R′ ≻ R` over the authority's root sequence. It is itself an authenticated non-membership,
i.e. the class of fact F.5a set out to discharge.

**Proposition F.5a.2 (prefix-uniqueness RELOCATES the non-membership obligation; it does not remove it).**
`authoritative(n)` at `t` is measurable in `ℐ` iff `ℐ` contains both `incl(n, A, R)` and `Cur(R, t)`.
Prefix-uniqueness supplies the first and is silent on the second.
*Proof.* Suppose `ℐ` contains only `incl(n, A, R)`. Take two histories agreeing on every byte of the bundle: in
`H₁` the authority's latest root is `R` and binds `n ↦ A`; in `H₂` a later root `R′ ≻ R` binds `n ↦ B ≠ A`,
while `R` and its proof remain exactly as served. `incl(n, A, R)` holds in both, so it is `ℐ`-measurable in
both, while `activeGenesis(n)` differs — hence `activeGenesis(n) = A` is not `ℐ`-measurable. Conversely, given
`Cur(R, t)`, `R = R_t` and uniqueness under `R_t` is uniqueness among active bindings. ∎

**The relocation is the gain, and it is strict.** The universe of the negation changes, and with it the class of
evidence able to settle it:

- **before** — non-membership over NAMES: `B` ranges over every genesis an adversary can construct. The universe
  is unkeyed and unbounded, nothing in it makes absence exhibitable, and only a trusted observer's report can
  stand in for the missing structure. This is why F.5a classes the publisher's served list as membership-only.
- **after** — non-membership over ROOTS: `R′` ranges over one sequence, totally ordered, produced by one party.
  Once the roots are committed to the anchor substrate, that sequence is embedded in a structure which is itself
  totally ordered in time, so `Cur(R, t)` is maximality in `{ R′ ∈ Fₜ : signed by m, R′ ≻ R }` — decidable in
  `Fₜ` from a view of the substrate that is complete after `R`'s anchor.

So the residual is not a trusted observer but SUBSTRATE-VIEW COMPLETENESS, which §11.3 already treats as a
named, measurable property. That is the honest statement of what the map route buys, and it is strictly weaker
than the elimination the phrase *the universal `¬∃B` collapses to a single positive lookup* suggests when read
alone.

**Proposition F.5a.2b (an unanchored pinned root supplies `Cur` by AXIOM, not by evidence).** Let the consumer
configuration `C` carry a set of admitted roots and let `R ∈ C` with no anchor coordinate for `R` in `ℐ`. Then
`Cur(R, t)` is decided by `C` alone and by no coordinate of `ℐ`, so by the discipline of Proposition F.5a.1 it
is a consumer axiom `Ax_C^cur` and must be LABELLED as one. The conjunction the verdict then reports is an
evidence fact (`incl`) and a consumer axiom (`Cur`) — a mixed statement, valid but UNDATED, and an undated
statement about a time-varying binding is read as a statement about now.
*Proof.* Identical in form to Proposition F.5a.1: the two histories `H₁`, `H₂` above agree on every element of
`ℐ` and differ on `Cur`, so no `ℐ`-coordinate decides it; `C` does. ∎

**Corollary F.5a.2c (the namespace authority is not derivable from the substrate — a negative result).** The
`C`-indexed part does not vanish. Deriving `activeGenesis(n)` from `Fₜ` alone by first-anchored-wins requires
proving that no earlier anchored binding for `n` exists — non-membership again, one level down, over a substrate
that commits opaque roots and therefore supports membership, not keyed lookup; enumerating it is the F.3.1
obligation restated. A root served from the publisher's own surface is self-referential, an authority named by
DNS or a well-known path returns the choice to the party the statement is about (excluded by F.5a.1 clause 2 in
substance), and trust-on-first-use was withdrawn with the `pinned` rung. Hence `authoritative` is NOT reachable
with an empty consumer configuration, and the correct claim for the map route is the reduction above: the
epoch-varying coordinate moves from `C` into `Fₜ`, leaving a `C`-part constant in the number of names and
constant in time.

**One admission, two typed spaces, two different obligations.** §12.3.4 admits both maps through the same
predicate, and their keys differ in temporal semantics:

- **name-map**, key `= (domain_shard)`: the bound value legitimately CHANGES on authority rotation. Missing
  `Cur` is an OVERSTATEMENT — a superseded binding verifies under its own root and reports the top identity rung.
- **checkpoint-map**, key `= (domain_shard, genesis_epoch, sequence)`: the coordinate is write-once by intent,
  so a later root binding a different value is equivocation, not authority rotation. Missing `Cur` is an UNCHECKED
  PREMISE — the write-once property is assumed, and its violation is exactly the event anti-equivocation claims
  to exclude.

Both need the coordinate named; they do not need different coordinates. The verdict reports the BASIS on which
currency is held, and the consequence of that basis is a property of the key space, stated here.

**Realization (rc.72 line, REV 69, completed REV 72).** The admission predicate returns a currency BASIS rather
than a boolean — `mapRootBasis(trust, root, token)` — and both call sites carry it into the verdict as
`map_root_currency`. REV 69 realized one value, `consumer-asserted`, and named the other as absent. REV 72
realizes it: `anchored-authority`, where the root arrives as a CLOSED signed statement admitted against the
consumer's `mapAuthorities` and is then proven included in the anchor substrate, minting an unforgeable token by
the same discipline as `VERIFIED_ANCHOR`/`VERIFIED_FRESH`. That is the factorization above, built: the
epoch-varying coordinate moved from `C` into `Fₜ`, the `C`-part became one entry per AUTHORITY rather than one
per root, and the verdict is DATED (`map_root_as_of`) from the anchor rather than from the signer — the claim
carries no time at all, by the round-35 rule that kept `valid_as_of` out of a signed claim. No tier moves for an
existing consumer: what was silent is labelled, and what was per-epoch is now one-time.

**Conformance (each claim is a running property — math ⇒ code ⇒ green check, `packages/ust-protocol/conformance.mjs`).**
- Proposition F.5a.2 (uniqueness is under a root, and a superseded binding still verifies under its own):
  *"F.5a.2 a SUPERSEDED name binding still verifies under its own root — uniqueness is UNDER R, not at t"*.
- Proposition F.5a.2b (the axiom is labelled, never silent): *"F.5a.2b a consumer-pinned map root reports map_root_currency consumer-asserted"*.
- The same coordinate on the second typed space (one mechanism, both surfaces):
  *"F.5a.2b the checkpoint-map surface carries the SAME currency coordinate"*.
- Fail-closed (no map coordinate without a basis): *"F.5a.2 a map root with no admission basis earns no map rung"*.

## F.5a.3 The rungs partition PREDICATES, not evidence bases — and the first argument for that was wrong (#151)

Two routes reach `authoritative`: an anchored map inclusion (F.5a b) and an accepted external witness (F.5a.1).
Whether they are one rung or two is a question about the LADDER, and it was first answered with an argument that
F.5a.2c refutes.

**The refuted argument, kept with its refutation.** It read: a rung must be decidable in the σ-algebra the ladder
climbs; the witness route is decided in the consumer's trust configuration `C`, which is not a world coordinate;
therefore it cannot be a rung. F.5a.2c shows the MAP route also bottoms out in `C` — the namespace authority is
admitted there and nowhere else — so the premise separates nothing and every conclusion resting on it is
unsupported. It is recorded rather than deleted because a correct decision defended by a broken argument is the
one most likely to be re-opened badly: the next reader who notices the flaw has no way to tell whether the
decision fell with it.

**Proposition F.5a.3 (one predicate, one rung).** Let `e₁` be an admitted map inclusion and `e₂` an admitted
witness attestation, both for `(n, A)`. Each yields the SAME proposition `¬∃ B ≠ A : B ∈ activeGenesis(n)`. A rung
is a strength of the fact ESTABLISHED, not of the manner of establishing it, so `σ(ℐ ∪ {e₁})` and `σ(ℐ ∪ {e₂})`
agree on the ladder's coordinate and the two are one rung. A ladder separating them would be ordering EVIDENCE
rather than assurance — the M1.3 category error F.5a corrects once already, arriving here from the other side. ∎

**What does differ, and where it belongs.** The routes fail differently, and the difference is structural rather
than a matter of degree:

- the map authority commits a TOTAL function over the key space with ONE signature — `bind(·, R)` is defined at
  every key — so a statement about `n` cannot be withheld without producing a different root, and roots are
  comparable and, once anchored, publicly ordered;
- a witness signs a claim ABOUT `n`. Evidence exists only where the witness chose to speak, so selective silence
  leaves no artifact at all.

The map's non-membership is therefore by CONSTRUCTION and the witness's is by TESTIMONY. That is a difference in
the FAILURE MODE of the evidence, which is what an admission policy `C` exists to price, and not a difference in
what was established, which is what a rung exists to record. Hence the basis rides as a FIELD and the tier stays
a projection of the axes alone.

**Corollary F.5a.3a (there is no fourth rung, and the reason is not a naming problem).** A rung above
`authoritative` would have to name a strictly stronger PREDICATE about the same coordinate. `¬∃ rival` admits no
strengthening — it is already universal over the rival space — so any candidate fourth rung would be a relabelled
evidence basis, which Proposition F.5a.3 excludes. Choosing a different word for it changes nothing, because the
objection is that there is no proposition left to order.

**Not taken on faith.** The claim that external confirmation is the least-used property of the protocol is
plausible and UNMEASURED. It becomes observable once the anchored route ships: the share of calls supplying
`trustRoots` or `noForkEvidence` against the share reaching the rung by inclusion. The decision is recorded now
and the number is attached later; if the number contradicts it, this section is re-opened with a new closing.

**Realization.** Measured, not built: `projectTier` reads the four axes and has never seen a basis, while the
verdict already carries `basis`, `noFork` and (round 216) `map_root_currency` beside the strength. The work here
is the invariant that keeps it so.

**Conformance.**
- Proposition F.5a.3: *"F.5a.3 two verdicts differing ONLY in evidence basis project to the SAME tier"*.
- the basis is not lost either: *"F.5a.3 the basis rides the verdict — one rung does not mean one story"*.

## F.5b Downgrade resistance is the consumer's floor, not the producer's promise

The tiers are totally ordered, `LIGHT < HIGH < TOP`, and by Theorem F.5 each is a coarser σ-algebra than the
next: `𝒮_LIGHT ⊆ 𝒮_HIGH ⊆ 𝒮_TOP`. Write `T(d, ℐ)` for the FINEST tier decidable for document `d` from an
information set `ℐ` — the verdict the reference verifier emits. Three facts pin its behaviour under an attacker
who can only DELETE evidence (strip the anchor `proof`, omit the genesis / key-log, hide the name-map):

- **Monotone erosion.** `ℐ' ⊆ ℐ ⇒ T(d, ℐ') ≤ T(d, ℐ)`. Every tier above LIGHT is earned by a coordinate that
  lives OUTSIDE the document bytes — the resolved key-log for HIGH (§F.5), the anchored map + substrate root for
  TOP (§F.5a, §F.3). Removing any such coordinate from `ℐ` removes it from the σ-algebra that decides the higher
  tier, so the decidable tier can only fall. Stripping is a coarsening, never a refinement.
- **No upward forge (`W1`).** `T(d, ℐ)` is never ABOVE the true tier the evidence supports: authority can be
  DENIED but not fabricated (F.3.1 / F.5a — non-membership and anchored time are not producible by the
  publisher). Evidence is necessary, not assertable; there is no header, flag, or self-claim in `𝒮_LIGHT` that
  raises `T`.
- **Consumer floor.** A consumer names a REQUIRED tier `R` and accepts `d` iff `T(d, ℐ) ≥ R`. This is the only
  place the ordering is USED: the floor is a comparison, not a coercion.

**Theorem F.5b (downgrade resistance).** Let a consumer hold floor `R` and let an attacker present `d` with an
eroded `ℐ' ⊆ ℐ`. Then either `T(d, ℐ') ≥ R` (the surviving evidence still earns `R` — a genuine `R`-grade
document, nothing was gained) or `T(d, ℐ') < R`, in which case the consumer REJECTS. There is no third branch:
because acceptance is `T ≥ R` and never "accept at whatever `T` came out," a strip that drops the tier below the
floor produces a rejection, never a silent accept at the lower tier. *Proof.* Immediate from monotone erosion
(the strip can only lower `T`) and the floor being a total-order comparison against a fixed `R`. Downgrade is the
floor doing its job; it is the consumer's CHOICE of `R`, never a forge succeeding (`W1` blocks the only other
route, raising `T`). ∎

**Corollary F.5b (the two floors are symmetric).** `requireAuthoritative` is the floor `R = HIGH`-authoritative;
`requireAnchored` is the floor `R = TOP`. A verifier MUST implement each as `T(d, ℐ) ≥ R ? accept : reject`. The
rejection NAMES the missing coordinate — a stripped/absent anchor proof ⇒ `E-ANCHOR` (a structural downgrade: the
document cannot reach TOP without a new proof), a non-authoritative identity ⇒ `E-GENESIS`, and an anchor that is
PRESENT and inclusion-valid but whose substrate is unreachable or not-yet-buried ⇒ `INDETERMINATE` (retry, `W1`:
the evidence may still arrive — this is unavailability, not a forgery). Absence of a floor is the LIGHT default,
where `T` is surfaced as-is; the floors exist precisely so a TOP-needing consumer cannot be handed a LIGHT doc.

**Realization (rev85 — domain totality).** the floor is the consumer's, so a stripped proof cannot pass it: stripping the proof under an anchored floor is rejected rather than silently downgraded — *"#45 requireAnchored: proof STRIPPED (authoritative HIGH) → E-ANCHOR (downgrade rejected)"*

## F.5c Fork-choice — anchor-inclusion is the choice function

A single time coordinate `ust_id` may have SEVERAL candidate documents `{d₁, …, dₙ}` with DISTINCT
`content_hash`es: the honest dual-writer race (main and failover both seal the slot, different arrival ⇒
different bytes), or an adversary offering two states for one slot. A consumer holding two of them must resolve
which is canonical WITHOUT trusting local arrival order — otherwise two consumers disagree, and "valid" stops
being a function of the data.

The resolvent is already in the model. The anchor journal `Fₜ` (§F.3) commits, per authority and per hour, a SET
of leaves — the hour's Merkle root, substrate-timestamped — a single totally-ordered, tamper-evident object. Define
the choice function

  `canonical(ust_id) = the unique dᵢ with content_hash(dᵢ) ∈ leaves(A_{auth}(hour(ust_id)))`,

where `A_{auth}(h)` is the anchored leaf-set of authority `auth` for hour `h`. Its well-definedness is a counting
statement about the operator's admission rule:

- **Election ⇒ uniqueness.** The store-NX election (a content-addressed conditional-write: the first writer to
  claim `ust_id` wins, §11 dual-writer) admits AT MOST ONE writer's document to the set that is later anchored.
  So in honest operation `|{ i : ch(dᵢ) ∈ A_{auth} }| ≤ 1`.
- **Exactly one anchored ⇒ that one is canonical.** The others are non-canonical LOSERS — not invalid (each may
  be a perfectly `VALID:HIGH` document; it simply lost the race and was never anchored for this slot). A consumer
  deterministically keeps the anchor-included one.
- **Zero anchored ⇒ `INDETERMINATE` at TOP.** No candidate is in `Fₜ` yet (the hour is still open, or neither was
  elected). Fork-choice is undecidable at TOP; the consumer resolves at HIGH by other means or WAITS for the hour
  anchor. This is unavailability (`W1`), not a fault.
- **Two or more anchored under ONE authority ⇒ `E-PREV` (equivocation).** `|{ i : ch(dᵢ) ∈ A_{auth} }| ≥ 2` with
  distinct `content_hash`es means the operator committed TWO states for one slot into an anchored root under one
  name — a non-repudiable, detectable fault. The anchor makes it PUNISHABLE: the operator SIGNED a root
  containing both, so equivocation is evidence, not deniable ambiguity. (Distinct authorities publishing the same
  `ust_id` are NOT a fork — canonicity is per-authority; each is canonical in its own `A_{auth}`.)

**Proposition F.5c (determinism).** Two consumers with the same candidate set and the same anchor `A_{auth}` emit
the SAME `canonical`. *Proof.* The choice reads only `content_hash(dᵢ)` (a function of the bytes) and membership
in `A_{auth}` (a function of the shared anchor); neither depends on arrival order or local state. So `canonical`
is a function of `(candidates, A_{auth})` alone. ∎ This is exactly the property §11 requires of the dual-writer:
"canonical = anchor-included" turns an operator-side race into a consumer-side FUNCTION — the loser is decided by
the chain, not by whichever document a given agent happened to fetch first.

**Realization (rev85 — domain totality).** equivocation is detected rather than resolved by guessing: two anchored rivals under one authority are an error, not a winner — *"#45 forkChoice: both anchored, one authority, distinct hash → E-PREV (equivocation)"*

## F.5c.1 The anchor seam — BOTH halves are the substrate's, and the connector is CONSUMER-injected (#95, rev91)

F.3 states the assumption; this section is where it is paid for. The anchor seam answers two questions — is
`content_hash` in the leaf-set committed by `root`, and is `root` final — and F.3 (rev91) moved the FIRST into the
substrate profile alongside the second. Delegation opens a forgery surface that must be closed, and the closure is
what licenses the assumption.

**A word collision worth naming, because it decides which discipline applies.** `Caps` (F.5.0) contains a member
spelled `inclusion`, and it is NOT the anchor seam's. That one is a capability DECLARED by a proof-kind
(`EVIDENCE_CAPS['transparency-log'] = {inclusion, consistency, order}`), earned only when a consumer-admitted
connector actually SIGNED the receipt, governed by B3 attenuation / B4 role / Theorem M3 — no caller mints it, and
admission is mandatory. The anchor path's `inclusion` is a SEAM VERDICT with no admission step at all. They share a
word, not a mechanism, and an implementer who fuses them either demands signatures where none are owed or drops
them where they are.

**Why a caller Boolean is admissible here without breaking C3.** C3 holds that a bare label or a caller Boolean
earns nothing — and that rule governs claims arriving IN THE DOCUMENT. The separation is structural rather than
policy: `verifyAnchorCore(ch, doc.proof, opts)` takes the proof from the PUBLISHER and the connector from the
CONSUMER, and a document is JSON on the wire — JSON cannot carry a function, so a publisher can never supply
`inclusionVerify` or `substrateVerify` at all, whatever it writes into its own bytes. The consumer's injected
verifier is the trusted BASE CASE of the anchor seam, not an exception to C3; a consumer that injects a lie is
lying to itself, which is outside every threat model here.

**F.5c's uniqueness never rested on the tree.** `canonical(ust_id)`'s well-definedness rests on `root` being the
AUTHORITY's anchored root — a substrate fact — and on the operator's election rule. An adversary can always build
its OWN tree containing two rival documents and present valid paths for both, so the walk never distinguished
them; only the substrate check does. Hence delegating the walk cannot weaken fork-choice.

**Realization (rev91 — inclusion delegated, and the four ways delegation could forge are closed).** `verifyAnchor`
takes `opts.inclusionVerify` through the SAME not-ours door as `substrateVerify`, and the tagged `ust:leaf`/`ust:node`
walk remains the bundled connector, so every proof already in the field still verifies with no adapter. Four surfaces, each closed:
- a capability planted IN the proof or its `Locator` earns nothing, and MEASUREMENT says the mechanism is stronger than "the connector is read from `opts` only": a function makes the whole proof non-inert and it is refused at the door — *"#95 a proof carrying a FUNCTION is refused at the door as non-inert — a capability cannot travel in data"* — while an inert look-alike is STRIPPED by admission, which copies only declared fields, so the seam never sees it — *"#95 a doc-borne DATA look-alike (anchor.inclusionVerify: true) earns nothing — the connector is read from opts only"*. Two independent layers, which is why no single mutant can falsify this one (recorded at the vacuity pin rather than papered over)
- the leaf is CLOSED and TYPED, so `'yes'`/`1`/`{}`/`[]`/`'true'`/`null` cannot mint inclusion — *"#95 a non-Boolean connector return cannot mint inclusion — typed closed leaf"*
- the door is TOTAL, so a throwing or revoked-Proxy connector yields a structured verdict rather than a host throw — *"#95 a hostile connector (throw / revoked Proxy) → structured reject, never a host throw"*
- delegation does NOT lift the time rung: anchored time still requires the substrate seam, so a connector answering `true` leaves `time: 'unproven'` — *"#95 an inclusion connector cannot mint anchored TIME — the substrate seam still gates it (C3)"*

Absent a connector, a foreign-shape proof is refused rather than silently accepted — *"#95 with NO connector the bundled walk still refuses a foreign-shape proof (no silent acceptance)"*

## F.5d Key-log freshness is the third face of authenticated non-membership

The revocation predicate "key `k` is still valid at time `t`" is `¬∃ e : e revokes k ∧ e ∈ keylog ∧ time(e) ⪯ t`
— a NON-MEMBERSHIP statement over the key-log, structurally identical to no-fork on the name axis (F.5a) and
snapshot-completeness on the time axis (F.3.1). By Corollary F.3.1 it does NOT follow from any positive view: a
consumer holding a cached key-log `L' ⊆ L` decides only `revoke ∉ L'` (membership in its own prefix), which is in
`σ(L')`, NOT in the σ-algebra that decides `revoke ∉ L`. The publisher (or a stale cache) can OMIT the revoking
entry exactly as it can omit a rival genesis. So freshness is earned by bringing the non-membership coordinate
into `ℐ`. **An earlier claim — that an anchored key-log HEAD alone settles `¬∃ later entry` and thus earns
`attested` — was UNSOUND (P0-03, external audit): an anchored head proves membership AT its anchor time, not that
it is the LATEST head at the target's time; a revoke that FOLLOWS the anchored prefix is invisible to it (the F.5a
"positive lookup settles ¬∃" transposition fails here because the key-log has no independent map coordinate, only a
prefix).** Strong key-log freshness is therefore not a single-anchor fact: `corroborated`/`attested` are earned ONLY
through the checkpoint derivation (F.5i/F.5j) — authorization ∧ strict terminality (F.5n) ∧ proven-after ordering ∧
independent uniqueness. A fetch from the authoritative surface timestamped `≥ t` still earns `fresh` (a single-view
report); neither ⇒ `unverified`. Emitting `unverified` (never a forged "valid") and letting the consumer floor on it
(`requireFreshKeylog`) is the F.5b discipline: the strong word is earned by the composed predicate, not bought by
assuming a cached prefix is the whole log.

**Realization (rev85 — domain totality).** a stale key-log cache cannot pass as fresh: a stale cache is INDETERMINATE, never quietly fresh — *"#40 requireFreshKeylog on a stale cache → INDETERMINATE stale_keylog"*

## F.5e.0 Why there is no `rotate` transition (rev97)

An earlier form of §F.5e carried a third transition — `rotate`, **signed by the key `s` it replaces**, naming a
successor `k`. It was defined here, present in the verifier's field allowlist, emitted by nothing, and covered by
no conformance check. Removing it is therefore not a compatibility question; no key log in existence contains one
(measured on the reference operator's served and mirrored logs, 2026-07-29). It is removed on its merits.

**The property that disqualifies it.** Compromise is TERMINAL only once DECLARED (§F.5e). A key compromised and
not yet declared is, by the admissibility invariant, still `active` — so it may sign `rotate(→k)` for a successor
the ATTACKER chose. The operator then revokes the key it knows about and the attacker retains authority through a
key the operator never saw. Self-authorized succession converts a detected compromise into an undetected one.

Contrast the root-authorized replacement, `add(k, supersedes=s)` + `revoke(s, retired)`: both events are signed by
a key the operator controls deliberately, and revoking `s` ends the incident because no successor exists that the
operator did not name.

**What is lost, stated honestly.** `rotate` let an honest operator roll a key forward WITHOUT bringing the root
out of cold storage. That is a real operational cost and it is paid deliberately: an offline root is protection
against exactly the scenario `rotate` reopens, so spending it to avoid touching the root is circular.

**What replaces it for §F.5e.1.** Role inheritance needs a successor relation, not self-authorization. `supersedes`
on a root-authorized `add` supplies it, and it satisfies §F.5e.2 — the verifier ACTS on the field: it derives the
successor's role from the superseded key's lineage, so the field is not decoration a verifier ignores.

**The relation must be ASSERTED AT BOTH ENDS, and round 82 found it was not.** `supersedes = s` names two keys:
the successor `k`, which the operator names by generating it, and the SUBJECT `s`. Nothing above constrains where
`s` comes from, and the reference producer took it from POSITION — the nearest preceding `add` in the log. That is
adjacency, reintroduced by the writer of the very field introduced to remove adjacency from the reader. With one
operational key it is correct by accident, since position and intent name the same key. §F.5e.1 then made two
active keys ordinary, and the accident ended: the tool superseded whichever key was added last, §F.5e.1's
inheritance derived `R(k)` from a lineage the operator never chose, and a `revoke(s, compromised)` — TERMINAL by
§F.5e — targeted a key the operator never named. The model layer is not incidental here: role inheritance is
*defined* as a function of the lineage, so a lineage chosen by position makes `R` a function of file order. The
obligation is therefore stated where the field is: **`s` is an operator assertion, never a positional inference**,
and a producer that cannot obtain the assertion must REFUSE rather than choose — the fail-closed direction, since
the act it would be guessing at is irreversible.

**Binding: realized** — *"rev97 op:rotate is REFUSED AS UNKNOWN — self-authorized succession is gone from the protocol"*.
The removal is not prose: `OP_FIELDS` names only `add` and `revoke`, so `op:"rotate"` is an unknown op and fails
`E-KEY`, and that check asserts the REASON rather than merely the refusal. This note
said the check "does not exist yet" and was stale for two rounds — measured 2026-07-29, the check and its vector
were already there. A pending-binding that outlives its own closure is the same defect as a realization note that
outruns the code, pointing the other way: the model under-claimed what runs, which reads to a reviewer as an open
hole and sends them to fix something already fixed.

CLOSED 2026-08-02 — *Closed in rev88 (2026-08-02), the round this corollary landed in, and noted here
afterwards:* `recoverHead` now goes through `recordFrame` — the same door an ordinary append uses — so
adoption moves the whole group, and the reference operator took it the same day. Noted 2026-08-05, appended
rather than rewritten.

CLOSED 2026-08-01 — *Closed in rev75 itself (2026-08-01), and this line was added afterwards:* `gap` and
`resume` were routed through the single guard, and the check became a WRITER ROSTER derived from the source —
every site writing the head key, resolved to its enclosing function and required to reduce to `advanceHead`.
Noted 2026-08-05, appended rather than rewritten.

CLOSED 2026-08-01 — on 2026-08-01 (rev77): `recordCheckpoint` refuses a store with no `del` (`E-STORE`) and
clears through the port, and the reference operator's port gained `del` and a status check the same day, so a
`400` is no longer indistinguishable from success. Written afterwards — the measurement above stands as it was
taken. Noted 2026-08-05, appended rather than rewritten.

CLOSED 2026-07-27 — on 2026-07-27, the day it was measured (rev95): the self-check now asserts what the
ceremony determines — the new key is in the ACTIVE SET after the grown log. The transition it tested was
itself removed in rev97 (F.5e.0), so the `rotate` bullet above no longer describes a form of this protocol;
both notes were written afterwards. Noted 2026-08-05, appended rather than rewritten.

## F.5e The key-authority process `K_n(t)` — a state machine, not a set (MATH-04, #75)

`W_n` (§F.5, §F.5a) bundled several facts; one of them — WHICH key is authorized for name `n` at time `t` — is
not a static set but a **process**. Model the key-log as a sequence of events `(e_1, …, e_m)`, each an
`add | revoke` transition (see the `rotate` removal below), and define the reducer

  `K_n : (event prefix) ↦ ⟨active ⊆ Keys, bind ⊆ Keys, revoked : Keys ⇀ {retired, compromised}×Time⟩`,

with `active` the keys that may sign the NEXT event, `bind` every key ever authorized (for document binding), and
the transitions: `add(k, supersedes?)` ⇒ `active ∪ {k}`, `bind ∪ {k}`, and when `supersedes = s` is present the
successor relation `succ(s) = k` is recorded; `revoke(k, r)` ⇒ `active ∖ {k}`, `revoked[k] = (r, t)`. Replacing a
key is therefore `add(k, supersedes=s)` followed by `revoke(s, retired)` — two events, both authorized by the
signer the admissibility invariant demands, with the succession stated rather than inferred. The **admissibility invariant** is `signer(e_{i+1}) ∈ active(after e_i)` — an event is well-formed only
if its signer was active in the state the PREVIOUS events produced. This is exactly the missing coordinate: "key
`k` appears somewhere in the log" (`k ∈ bind`) is strictly weaker than "`k` was active when it signed" (`k ∈
active` at that prefix), and conflating them is the P0-02 class (a revoked / rotated-out key still signing).

**Event preconditions — COMPROMISE is TERMINAL (made normative rev67, round-47 P1-02).** Beyond the signer being active, one
TARGET precondition is load-bearing: once `revoked[k] = (compromised, ·)`, `k` is TERMINAL — no later `add(k)`, `add(·, supersedes=k)`,
or `revoke(k, ·)` is admissible (compromise is monotonic; it can never be re-authorized, re-revoked, or downgraded to
`retired`). An event violating it is INADMISSIBLE (the reducer errors `E-KEY`), exactly as a non-active-signer event is.
`revoke(k, r)` also requires `k ∈ bind` (a never-authorized key cannot be revoked). It does NOT require `k ∈ active`: a
redundant revoke of an already rotated-out / retired (non-compromised) key is admissible and harmless — the key is already
inactive, and a nondecreasing timeline means the redundant revoke can only move the retirement time LATER, never un-retire (so
soundness is untouched). This terminality precondition was realized in `resolveKeys` from the start but was NOT stated here —
the round-47 audit showed the temporal model check had copied it from the IMPLEMENTATION rather than this spec, so its
differential could not adjudicate it (a shared blind spot); the audit also probed a stricter `revoke ⇒ target-active` rule and
this spec ADJUDICATES it as unnecessary (harmless). Terminality is now normative, and `temporal-bmc.mjs` enumerates EVERY
one-step transition it excludes (re-revoke a compromised key, re-authorize a compromised key) as an ATTACK and asserts the
reducer rejects it — the differential is no longer the sole witness.

**Realization (representation note).** `K_n` is realized by `resolveKeys(genesis, keylog)` → `{active, validKeys
(=bind), revoked, history, head}`; the invariant is the `active.get(keyId(sig.pub)) === sig.pub` gate per entry;
the closed per-`op` schema is the well-formedness of each event. Document authority reads `bind` (continuity) then
the §12.2 X1 predicate judges `revoked[k]` at the document's time — a query of `K_n` at `t`. **The query time `t`
is the PROVEN anchor upper bound `U` (ROOT 1 / MATH-05, done): `verify` runs in two phases — it verifies the anchor
FIRST, then resolves authority with that proven `U`, so revocation / retirement / freshness are decided against
the chain, not a caller-supplied or absent time.** `K_n(t)` is a WINDOW, `authorized_at(k) ≤ U ≤ end(k)`: the
lower bound is the new `premature` verdict (a document cannot be proven-anchored before its signing key was
authorized), the upper bound is the X1 retired/compromised predicate. The `authority-at-time` vectors exercise the
window; the `keylog-state` vectors exercise the reducer invariant — both are executable instances a second
implementation runs through its own `K_n` and must match. (The `authorized_at` lower bound uses the key's CLAIMED
authorization time; making it an ANCHORED lower bound is the operator manifest, ROOT 3.)

**Realization (rev85 — domain totality).** the process needs a PROVEN U, not an assumed one: a retired key with an unanchored document is refused authority — *"P0-01 retired key + UNANCHORED doc → NOT authoritative (fail-closed, K_n needs a proven U)"*

## F.5e.1 Key ROLE partitions `active`; the carrier is decided by well-foundedness, not by preference (rev96, re-derived round 79)

`K_n` (§F.5e) reduces the key-log to `⟨active, bind, revoked⟩`, and `active` is one undifferentiated set: every
key that may sign the next event may sign ANY document the name publishes. An operator that signs two kinds of
thing — a data stream and something handed to a named recipient — therefore has no way to say so, and a consumer
reading the log cannot tell that two signatures were meant differently. The consequence is not expressive: a
single leaked key signs everything the publisher has ever been able to sign, and revocation is all-or-nothing
because there is exactly one thing to revoke.

**The extension.** Let `Role` be a finite set fixed by the specification. `active` becomes a family indexed by
role:

  `K_n : (event prefix) ↦ ⟨ active : Role ⇀ 𝒫(Keys), bind ⊆ Keys, revoked : Keys ⇀ {retired, compromised}×Time ⟩`

and the document-admission predicate gains the role coordinate: `admits(k, c)` holds iff `k ∈ active(r)` for some
`r` whose normative class-set contains `c`. `bind` and `revoked` are unchanged — a key's history is not
role-relative, only its present authority is.

**The normative class-sets, without which the predicate cannot be evaluated (rev89).** Until this revision the
sentence above defined `admits` in terms of a class-set that was never stated, so no verification path could
call it: three of the five roles authorized (each enforced where its object is verified) and the two an
operator actually ASSIGNS authorized nothing. One word, two mechanisms — the collision this model names
elsewhere, inside a single vocabulary.

  `name-binding-root ↦ {genesis, key, cadence}` · `data ↦ {observation, derivation, attestation}` ·
  `issuance ↦ {attestation}`

**The root is in the table (rev91), and F.7c is why.** A closed vocabulary that leaves one member without a
stated meaning has the identical defect for that member as an open field would for all of them: “what did this
signature mean” becomes a question addressed to the publisher. The root's set is its FUNCTION — bind the name,
authorize the log — which is the key context and nothing else. This is NOT containment and does not pretend to
be: a compromised root simply adds itself a `data` key. What it buys is that the addition leaves a SIGNED,
CHAINED entry in the public key log, so a quiet act becomes a loud one; and it makes the declaration honest —
a publisher that says “I separate my keys” now says it about the strongest key too, instead of about everyone
but itself.

*Enforced only under a DECLARED regime, and that condition is load-bearing.* The root carries its role always,
declared or not, so an unconditional check would refuse every document of a minimal publisher that signs with
its own root and keeps no key log. “A publisher that does NOTHING is unaffected in every respect” is the
invariant, and one condition is what keeps it true — the same condition that was correctly REMOVED in rev89 as
unreachable, and is reachable now precisely because the root joined the table.

**Why that cut and not another.** An issued document ATTESTS to what the publisher observed; it does not CREATE
the observation. So a leaked `issuance` key may re-state what the stream already contains and may never mint a
primary `observation` or a `derivation` — which is the containment the role exists for, expressed as a
capability rather than as a name.

*The class-sets are deliberately NOT disjoint, and this is not a weakening.* F.5e.1 partitions the KEY set
(`active : Role ⇀ 𝒫(Keys)`, one role per key), not the class space; `issuance ⊊ data` is a hierarchy of
capability over a partition of keys, which is exactly how the ceremony-set roles already read.

*And the failure is a REFUSAL, never a downgrade.* The key is bound — the publisher's own log declares it and
declares what it is for, and the document is outside that. Falling to `self-asserted` would leave the document
VALID at the LIGHT floor, which is the precise outcome the role exists to prevent. `E-KEY`, as the ceremony
roles already answer.

*Open (#130): what the ROOT admits under a declared regime.* `name-binding-root` has no operating class-set, so
today a root key signs any class even where separation is declared. Arguably a publisher that separates roles
wants its root cold; that is a policy decision this revision does not take, and it is recorded rather than
resolved by silence.

**Where roles are assigned.** The genesis fixes part of the assignment, exactly as it already fixes the
checkpoint-recovery set — §F.5l states that "Genesis fixes a checkpoint-recovery key set `RK` (role-separated from data and
checkpoint keys)", so role separation at the genesis level is an existing shape of this model. What that section
could not settle, and asserted instead, is whether the genesis fixes ALL of it.

**The rev96 argument for genesis-ONLY assignment no longer holds, and is withdrawn.** It ran: §F.5e's
admissibility invariant is `signer(e_{i+1}) ∈ active(after e_i)`, so **any** active key may sign the next event;
a key-log role therefore lets a COMPROMISED data key append `add(k, role=issuance)` and sign as that role, and
role separation is defeated by the compromise it exists to contain. That was sound when written. §F.5e.3 (rev97)
and round 76 then made key-log mutation ROOT-ONLY, so a non-root key can append nothing at all: the attack is
unreachable by construction. A conclusion whose only stated premise has been removed is not a conclusion, and
re-deriving it is cheaper than defending it.

**Genesis-ONLY assignment is inconsistent with two rules this same section states.** Let `R(k)` be the role of
`k`. Under genesis-only, `R(k)` is defined iff the genesis names `k`, or `k` supersedes some `s` with `R(s)`
defined (transitively, terminating at a genesis-named key). Now take `add(k)` with NO `supersedes` — permitted by
§F.5e (`add(k, supersedes?)` inserts a PARALLEL active key), and the ordinary way to introduce a key for a
DIFFERENT purpose rather than to replace one. Then `k` is not genesis-named — it did not exist at ceremony time —
and inherits from nothing, so `R(k)` is undefined; and by the no-default rule below, an unroled key is
INADMISSIBLE. **A transition the model admits therefore produces a key the model forbids from ever signing.** That
is not a cost to weigh; it is three rules of one model that cannot all hold.

The corollary is sharper than the inconsistency. Under genesis-only, "adding a role that no genesis names remains
a supersession" makes the ONLY way to introduce a new role a re-rooting of the name-binding genesis (§12.1 P2,
F.5m). An ordinary operational act would then be expressed as an IDENTITY event — a category error, since the
genesis answers *who the publisher is*, never *what its keys are for*. Routine role changes would make the root's
own signal noisy, which is the opposite of what pinning it is for.

**The carrier is decided by WELL-FOUNDEDNESS.** A role whose keys AUTHORIZE the key log cannot be assigned by the
key log: the log's own authority derives from those keys, so assigning them there is circular. A role whose keys
merely OPERATE under the log has no such obstruction. The split is therefore not a preference:

  · `name-binding-root`, `checkpoint-recovery`, `authority-checkpoint` — authorize the log ⇒ GENESIS-fixed, by well-foundedness
  · `data`, `issuance` — operate under it ⇒ assignable at `add`, root-signed

**And admitting `role` widens the FIELD set without widening the AUTHORITY set.** After §F.5e.3 an `add` is
signed by the root, so `add(k, role=r)` demands exactly the cold key a genesis supersession demands. What changes
is where a consumer READS the answer — and a consumer already reduces the whole log to resolve which key signed a
document, so reading a role from it costs nothing it was not already paying. §F.5e.2's admission criterion is
met: the verifier ACTS on `role`, since it partitions `active` and gates `admits(k, c)`.

**Theorem (role assignment is a RESTRICTION).** For every key `k` and document class `c`:

  `admits_role(k, c) ⟹ admits_flat(k, c)`

where `admits_flat` is the pre-role predicate of §F.5e. *Proof.* `active(r) ⊆ active` for every `r` by
construction, and the role-aware predicate additionally requires `c` to lie in `r`'s class-set; both conjuncts
only remove pairs. ∎

The theorem is what makes the extension safe to introduce: no verdict that was INVALID can become VALID, so the
change cannot widen authority under any key log, adversarial or honest. A design in which an unroled key defaults
to membership in every `active(r)` would satisfy the theorem trivially and is nevertheless rejected below.

**No default: within a role-declaring publisher, an unroled key is INADMISSIBLE.** A missing role must not grant
maximal authority, which is what a permissive default does — the absence of a field would become the strongest
possible claim, and the fail direction for an authority question is closed (§F.5e, and the general rule that
"is it safe?" fails closed while "is it relevant?" fails open).

**But the regime is DECLARED per publisher, and that too is derived rather than chosen.** rev96 said backward
compatibility "is not purchased here — a domain that predates roles supersedes its genesis". That cannot stand
against a normative law this protocol already carries: §11.3's continuity rule, *an operator change never
invalidates old data*. A publisher that does NOTHING must not stop verifying because the protocol gained a
concept; otherwise a verifier update rewrites verdicts on documents already issued, which is exactly what I4 and
the continuity law forbid — and the operator who broke is the one who made no change at all.

So role separation is a DECLARED refinement, the same shape as every other strength here: the genesis declares
it, and only then does `admits` consult roles and an unroled key become inadmissible. A publisher that declares
nothing keeps `admits_flat` (§F.5e) and loses only the strength, never validity. This is the LIGHT-floor
discipline applied one level in: a refinement no publisher declared cannot be demanded of documents signed before
it existed.

**Succession carries the role; the lineage does.** Binding a role to a `key_id` alone would make replacing a roled
key impossible without a supersession — rigidity with no security gain, since the replacement is authorized by the
root either way. So the role also attaches to the LINEAGE: `add(k, supersedes=s)` transfers `s`'s role to `k`
when `k` declares none. Inheritance PROPAGATES a role; it can never INTRODUCE one, which is precisely why an
explicit `role` on `add` is required rather than optional sugar — a parallel key has no lineage to inherit from.

An earlier draft of this section put the inheritance on `rotate` — the self-authorized transition — and that was
wrong for a reason that has nothing to do with roles: see §F.5e.0. The correction does require a key-log field,
and `supersedes` earns entry under §F.5e.2 precisely because the verifier ACTS on it to derive the role.

**Binding: pending — thelabmd/UST-Protocol#158.** This section states a design the implementation does not yet
carry, which is the point of stating it first.

**Two paragraphs stood here until round 79 and are removed rather than edited, because both described `rotate`.**
One deferred the code obligation "until `rotate` is emitted"; the other called reviving `rotate` a prerequisite of
this section. `rotate` was REMOVED in rev97 (§F.5e.0) — self-authorized succession let a compromised, undeclared
key name its own successor — and the correction three paragraphs above already re-based inheritance on
`supersedes`. The two notes were written for the pre-rev97 draft and survived the sweep that replaced the
mechanism they name, so this section simultaneously said that it depends on `supersedes` and that reviving
`rotate` is its prerequisite. Recorded rather than silently deleted: a sweep that fixes a mechanism and leaves
the prose that justifies it is the recurring failure this model keeps naming, and it happened here to the section
that names it.

## F.5e.2 What may enter a strict field allowlist (rev96)

`OP_FIELDS` rejects any key-log field it does not name (`E-MALFORMED`, "stray field"). That strictness is
load-bearing: it prevents a publisher from placing meaning into a signed entry that the verifier will not read,
which would let two parties disagree about what a signature said while both verify it.

Widening the allowlist is therefore a specification act, and admits exactly one criterion:

  **A field may enter the allowlist only if the VERIFIER ACTS ON IT.** A field the verifier ignores stays
  forbidden, regardless of how useful it is to a publisher or a reader.

`role` DOES enter, under the re-derivation in §F.5e.1 (round 79): the three authorizing roles stay genesis-fixed
by well-foundedness, while `data` and `issuance` are assigned on a root-signed `add`, and the verifier ACTS on the
field — it partitions `active` and gates `admits(k, c)`. Until round 79 this section said the opposite ("no
key-log field is required at all"), correctly reporting §F.5e.1 as it then stood; when that section's own security
premise was withdrawn, the consequence recorded here became stale with it. The criterion itself is unchanged and
is what admits the field: a verifier that ignored `role` would have to keep refusing it.

**Binding: none — definitional.** The section defines the admission criterion for a set the checker already
enforces (`OP_FIELDS` rejects any unnamed field); it imposes no obligation of its own beyond that enforcement.


## F.5e.2a The criterion of §F.5e.2 governs the INPUT, and inverts on the OUTPUT (rev98)

§F.5e.2 admits a field to a signed document only if **the verifier ACTS ON IT**. That criterion is sound where it
was written — over `OP_FIELDS`, the fields a publisher may place inside a signature. Applied to the record the
verifier RETURNS it is not merely wrong but meaningless: a verifier acts on none of its own output fields, it
produces them. Reading it that way forbids every field of every answer.

**The criterion inverts across the boundary.** For an input field the question is whether anyone downstream reads
it; a field nobody reads is a place for two parties to disagree while both verify. For an OUTPUT field the question
is the reader's: a field is admissible, and becomes REQUIRED, exactly when **without it two different answers are
indistinguishable to the consumer that must act on them.**

*This is not hypothetical here, and the measurement is the argument.* Two calls in this core answer different
questions under the same field name `result`. The §14 verdict answers "is this document valid" over
`{VALID, INVALID, INDETERMINATE}`; `forkChoice` answers "which candidate is canonical" over
`{CANONICAL, MULTI_AUTHORITY, INDETERMINATE, REFUSED}`. Measured 2026-08-10: the two vocabularies **intersect at
`INDETERMINATE`**, and a §14 verdict record is `{result, error, detail}` while a fork-choice record is
`{kind, result, error, detail}`. A consumer holding a record that says `INDETERMINATE` therefore has exactly one
thing separating "this document could not be judged" from "no candidate could be shown canonical": the presence of
`kind`. Under the input criterion that field would be forbidden — the verifier does not act on it — and the two
answers would be one.

The COLLISION itself is **STANDING**: two questions still answer under one field name, and renaming either
vocabulary is a breaking change tracked as thelabmd/UST-Protocol#111. What is **CLOSED** (2026-08-10, round 199)
is the consequence — the two answers are no longer indistinguishable, because the discriminator is now stated
normatively, registered, and enumerated over every return rather than asserted in a comment.

**Corollary (the discriminator is ASYMMETRIC, deliberately).** The §14 verdict carries no `kind`, and adding one
for symmetry would be a breaking change to every consumer already reading verdicts. The rule is therefore
one-sided and must be stated as such: `kind` PRESENT means the record is not a §14 verdict; `kind` ABSENT means
it is. A future answer that is neither must introduce its own `kind` rather than rely on absence.

**Corollary (a discriminator is only as good as its TOTALITY).** A record shape that carries the field on ten
paths and omits it on the eleventh is worse than one that never had it: the consumer's test succeeds often enough
to be trusted and then silently reports a fork-choice outcome as a verdict. Measured 2026-08-10: all 11 returns of
`forkChoice` carry it — and nothing enforced that. The property was asserted in a REGISTRY comment ("every return
now carries `kind: 'fork-choice'`") and checked by no executed artifact, which is this repository's recurring
defect class: a rule stated in prose beside the code it describes, with no carrier. CLOSED 2026-08-10 (round 199)
— `spec-code-sync` now enumerates the returns of `forkChoice` and fails on any that omits the registered
discriminator.

**Binding: none — definitional.** The section states the admission criterion for output fields; the obligation it
implies over this core is enforced by the enumeration named above, not by this section.


## F.5e.3 Authority to MUTATE the key log is not authority to SIGN (rev97)

§F.5e's admissibility invariant asks one question of an entry's signer: `signer(e_{i+1}) ∈ active(after e_i)`. That
is sound for the property it was written for — no unauthorized key may extend the log. It is silent on a second
question that turns out to matter more: WHICH active key.

**The measurement.** Against the reference implementation, 2026-07-29: a key added as an operational signer added a
further key, and that key's documents verified `authoritative`; the same operational key revoked the GENESIS key
with `reason:"compromised"` and was accepted. Compromise is terminal (§F.5e), so the second is irreversible.

**Why this is worse than the transition removed in §F.5e.0.** `rotate` gave a compromised key a successor. This
gives it the root's destruction, and gives it to the key an operator necessarily exposes: the operational key lives
in a running service's environment, while the root is kept offline PRECISELY so that exposing the operational key
stays survivable. The invariant made the second key as powerful as the first, nullifying the separation the
operator paid for.

**The correction.** Let `mutating(c)` hold for the classes that change WHO MAY SIGN — the key log — and, by the
same argument, the cadence log, which changes what the operator's own COMPLETENESS claim means. Then admissibility
gains a second conjunct:

    signer(e_{i+1}) ∈ active(after e_i)  ∧  (mutating(class(e_{i+1})) ⟹ signer = root)

The first conjunct is unchanged, so every sequence admissible after the correction was admissible before it: the
change is a RESTRICTION, and no document that verified under the old rule and does not mutate the log is affected.
Sequences it newly rejects are exactly those where a non-root key extended the log — which is the hole.

**Neither recovery mechanism is admitted, and the reason is a lesson.** The obvious objection is that a LOST root
strands the name forever. Two mechanisms answer that, and a first draft of this section admitted one of them here
on the strength of its name alone:

- **checkpoint-recovery** (§F.5l, §12.3.2) — a genesis-fixed threshold that re-authorizes the AUTHORITY CHECKPOINT
  chain. Its keys never sign key-log entries; they threshold-sign a `RecoveryClaim`. Measured while writing this:
  such a key signing a key-log entry is already refused as NOT-ACTIVE. The implementation was right and the
  reasoning was what was wrong.
- **genesis-recovery** (§12.1 P2) — re-rooting through DOMAIN CONTROL, which is the arbiter above the key log
  entirely. It does not need a key-log privilege because it operates on the layer that authorizes the key log.

Both were called "recovery" in prose until rev97 qualified them. A word that spans two mechanisms will eventually
be reasoned about as one, and here that reasoning would have widened an authority set — a security regression that
reads as a clarification. The qualified names now make the mistake unwriteable: "checkpoint-recovery keys may
mutate the key log" states its own error.

**One key, therefore.** Every key-log mutation traces to the single key the genesis self-signed with. That is the
strongest statement the structure supports and the simplest to reason about: no set to enumerate, no second party
to compromise.

**The cost, stated rather than absorbed.** No key may be added or revoked without the root, so an operator brings it
out of cold storage for every key-log mutation — for a typical operator, the once-a-year rotation its tooling
already warns about. The operator's decision, in their own framing: the key is theirs, and their actions or their
compromise, full stop. A protocol cannot carry this risk on the operator's behalf, and pretending otherwise moves
the failure somewhere less visible.

**Realization — round 76 completes `mutating(c)`: both classes, same conjunct, same shape.** For `class:"key"` it is
`resolveKeys` (three conformance vectors, the temporal BMC's illegal-transition sweep). For `class:"cadence"` it is
`resolveCadenceBytes`, added in the same shape rather than a second one: `keyId(sig.pub)` must be `active` AND must
equal the genesis key id. The key log stays load-bearing under a one-key rule because it is what reveals a REVOKED
root — *"#107 a REVOKED root may NOT move the grid (the key-log is still load-bearing under a one-key rule)"*.
Vectors: the CONTROL — *"#107 CONTROL: the GENESIS ROOT moves the grid 30s→3600s → accepted (the restriction is not a blanket refusal)"* — and the refusal, *"#107 an OPERATIONAL key may NOT move the cadence grid — `active` is NECESSARY, not SUFFICIENT"*; the byte-level oracle is `cadr-09-nonroot-signer-rejected` against the positive
`cadr-04/05/06`, so a second implementation cannot pass by refusing every change.

**The measurement corrected the ATTACK's shape, and the correction is recorded rather than quietly absorbed.** The
issue was filed on 30s→3600s. That widening does NOT hide holes: it crosses a precision class, the surviving frames
fall off the coarser grid, and #75 P0-04 grid EQUALITY already returns `E-PREV` — *"#107 boundary (measured, not assumed): widening ACROSS a precision class is caught by grid EQUALITY, not by this rule → E-PREV"*. The reachable
attack is a widening INSIDE one class: 30s→90s leaves every frame ON the grid, so a stream with two empty slots
reads `complete` with nothing added — *"#107 mutation-proven (b)"* against *"(a)"* and *"(c)"*. This matters beyond
bookkeeping: the working attack is the SMALL step, so the intuition that a dramatic jump is the thing to watch for
would have looked for the wrong signature entirely. A refusal whose flip was never measured is a refusal that might
have been defending against nothing.

An earlier draft of this section hedged the cadence clause as "insofar as a profile treats cadence as authority".
The hedge is the wrong shape and is withdrawn: a verifier cannot ask a profile at verification time, so a rule
conditioned on one is not a rule.

**Binding: realized — thelabmd/UST-Protocol#107 closed.** The general role vocabulary is carried by #158; it
GENERALIZES this conjunct and does not replace it.

## F.5e.4 The verification ROLE is a partition of classes, and a one-sided partition is not one

§14 runs one of two ROLES over a transcript: `key`, where a document is read as part of the trust layer — a
genesis, a key-log entry, a cadence entry — and `data`, where it is read as a publisher's claim about the world.
Which role applies is not a caller's preference; it is fixed by the document's `class`, because the two roles run
different downstream algorithms and a document that could be read as either would have two meanings.

**The map `role : Class → {key, data}` must be a PARTITION** — total (every registered class has a role) and
disjoint (no class has both). Only then is "which algorithm applies" a function of the document rather than of
the door it arrived at.

**A partition enforced on ONE side is not a partition.** If the `data` role refuses authority classes but the
`key` role admits everything, then the classes are not partitioned at all: a data document simply has two homes,
and the role it ends up in is decided by which caller reached it first. The asymmetry is invisible to a reader
of either check alone, because each looks like a correct refusal of the wrong thing.

**Measured 2026-07-29.** That is exactly what the reference implementation carried. `context:'data'` refused
`genesis`/`key`/`cadence`; `context:'key'` checked nothing, so a key-form `class:"observation"` verified
`VALID:LIGHT` in the key role, and the shared served-log reader — one parser for both the key log and the cadence
log — accepted it as a log entry. No verdict was wrong: the reducers still refused it by class one layer down. But
the door that reported having VERIFIED the entry was not the door that refused it, and a fail-closed reader whose
refusal lives elsewhere is only accidentally closed.

CLOSED 2026-07-29 by `6488eb0` — protocol(round 78): the verification ROLE is a partition, and it was
enforced on one side only (#97/tlx). The guard this paragraph explains landed with it; noted 2026-08-05,
appended rather than rewritten.

The correction is one enumeration read in BOTH directions rather than two lists that happen to agree today:
`key` admits exactly `{genesis, key, cadence}` and `data` admits exactly the complement. A class added to the
registry then belongs to a role by construction, instead of silently belonging to both.

**Realization — round 78.** `verify` derives both refusals from the single `AUTHORITY_CLASSES` set, so the two
directions cannot drift apart; the shared reader's own justification no longer rests on the key role admitting
everything. Cf. *"#97/tlx a data class in the KEY role → E-MALFORMED (the partition is two-sided)"* and
*"#97/tlx the key role admits EXACTLY the authority classes — genesis, key and cadence, measured from the set"*.

## F.5f Composite authority is TRANSITIVE — the impersonation fix needs no new signed object (#75 ROOT 3)

An external audit proposed closing the composition holes (an impostor becoming `canonical` / `complete` under a
victim's name, P0-03; off-grid commitment grinding, P0-04) with a new **operator-signed HourManifest**. The math
says that is unnecessary, and shows *why* — resolving two apparent dilemmas ("sign the hour root or not?", "typed
leaf or raw hash?") by direct computation rather than taste.

**Proposition F.5f.1 (impersonation is a per-frame authority failure, not a missing manifest).** A candidate `d`
claiming authority `A` for slot `s` is canonical-under-`A` only if `key(d) ∈ K_A(t)` (§F.5e). The impersonation
verdict is `key(d) ∉ K_A` — decidable in `σ(K_A)` from the genesis+key-log ALONE (ROOT 1+2), independent of any
anchor or manifest. So `forkChoice`/`verifyStream` must read the RESOLVED authority `A` (the name the resolved key
binds), never the LIGHT `domain_shard` CLAIM in the bytes. The claim is in `𝒮_LIGHT`; the binding is in `σ(K_A)`;
conflating them was the whole bug. No new object closes a σ-algebra gap that `K_A` already decides.

**Proposition F.5f.2 (the hour root carries no information a signature could add).** Let the hour's leaves be the
frames `d_1…d_m`, each already `A`-authenticated (F.5f.1), and let the expected grid be `G = grid(from, to,
cadence)` where `cadence` is `A`-signed (F.5e cadence log). The hour root `R = merkle(d_1…d_m)` and the
completeness predicate `{d_i} ⤳ G` are DETERMINISTIC functions of already-authenticated inputs. A signature over
`R` is therefore in `σ(K_A, {d_i}, cadence)` already — it adds no measurable event (the same reason `content_hash
= H(canon(state))` is not separately signed: it is a function of the signed state). Hence an operator hour root
is correctly UNSIGNED; its trust is (i) the `A`-authenticated leaves, (ii) the `A`-signed cadence, and (iii) the
substrate anchor for TIME + immutability (`Fₜ`), NOT an operator signature. The prod notary reached this
empirically (git+OTS, unsigned root); F.5f.2 is the reason.

**Corollary F.5f.3 (the typed leaf is redundant).** `content_hash(d) = H("ust:state", canon({ust, state}))` and
`state.id` contains `domain_shard` and `ust_id`; so `content_hash` already COMMITS the coordinate
`(domain_shard, ust_id, value)`. A leaf `H("ust:frame", canon({domain_shard, ust_id, content_hash}))` re-commits
what `content_hash` commits — no separation gained. The raw `content_hash` IS the coordinate-bound leaf.

**What the anchor is still load-bearing for** (not dissolved): (a) **canonicity among `A`'s OWN candidates** — a
dual-writer race yields two `A`-authenticated values for `s`; the one in `A`'s anchored set is canonical
(`forkChoice` via the substrate proof it already takes) — the store-NX election puts exactly one there, ≥2 ⇒
equivocation ⇒ `E-PREV`; (b) **standalone completeness** for a consumer who holds NONE of the frames — the
operator serves the anchored, deterministic (unsigned) hour index; this is an operator-profile artifact (§20),
not a new protocol primitive. (c) The remaining `latest-head` freshness (P0-05) is F.5a/F.5d authenticated
non-membership — the one composition problem that genuinely needs the anchored monitorable single-head, tracked
separately. The audit's manifest collapses, by the math, to "per-frame `K_A` + `A`-signed cadence + the existing
substrate anchor" — less machinery, each omission proven, not cut.

**Realization (rev85 — domain totality).** transitivity is what refuses the impersonation, with no new signed object: a checkpoint whose carried key is not the prior-authorized signer is refused — *"AC carried current_key_id ≠ prior-authorized signer → INVALID(E-AUTHORITY)"*

## F.5g.0 The verified authority context — scope is DERIVED, never chosen (M2, rc.36)

Every theorem from F.5g on binds objects to an AUTHORITY SCOPE. The rc.35 round-2 audits showed the scope parameters
were read from the very objects being verified — the publisher chose the terms of its own audit (epoch-split,
cross-domain, re-root). M2 fixes the root: ONE seam derives the scope from a VERIFIED genesis, and every downstream
layer takes the derived context, never raw fields.
**Realization (rev25 — one authority root).** When a branded `context` (a `GenesisHandle`) is supplied to
`verifyAuthorityCheckpointChain` / `deriveCheckpointFreshness`, it is the SOLE root: the entire raw authority-root
family (`pinnedPrior`, `genesis`, `genesisAuthority`, `recoveryKeys`, `recoveryThreshold`) alongside it is rejected
`E-AUTHORITY` — a foreign `pinnedPrior` cannot seize the chain scope/authority and raw checkpoint-recovery cannot be injected,
neither while reporting `verified-context` (*"C1/L1 a raw pinnedPrior alongside a branded context → INVALID(E-AUTHORITY) — the context is the SOLE root (never raw fields, M2; round-26 P0-01)"*, *"C1/L2 raw recoveryKeys/recoveryThreshold alongside a branded context → INVALID(E-AUTHORITY) — checkpoint-recovery is genesis-fixed, never injected from a call argument (F.5l; round-26 P0-02)"*).

**Realization (rev28 — the whole authority graph crosses ONE snapshot boundary).** rev24 put the inert `admitDeep`
snapshot on the evidence/genesis-context entries but not the chain verifier, so `verifyAuthorityCheckpointChain` /
`resolveCheckpointRoots` / `verifyCheckpointRecovery` held LIVE caller references and re-read them after signature
verification — a getter signed a no-rotation authority checkpoint body then minted an attacker rotation, a raw genesis TOCTOU
installed an unsigned authority, and a checkpoint-recovery getter re-signed the quorum (round-27 P0-01/02/03). Now **the WHOLE
authority graph crosses the ONE inert snapshot boundary**: `(chain, config)`, the genesis, and every checkpoint-recovery statement
are `admitDeep`-snapshotted at entry (a branded handle passes through; a getter/accessor at any depth is `E-MALFORMED`),
so classification, signature, ID, state transition, return value and pin are all functions of the SAME frozen bytes
(*"round-27 P0-02 a getter on an authority checkpoint body cannot sign one body and mint another → INVALID(E-MALFORMED) (the chain crosses the snapshot boundary)"*). The witness resource budget `ρ_v.time` is checked AFTER every awaited leaf, so
**a budget exhausted on the FINAL awaited leaf** is `INDETERMINATE(resource_limit)`, not a false `pending`
(*"round-27 P1-01 a budget exhausted on the FINAL leaf → INDETERMINATE(resource_limit), never reported as pending"*),
and **ONLY an ABSENT budget selects the reference default** — a supplied non-(finite positive integer) is refused, never
silently expanded (*"round-27 P2-01 invalid maxWitnessOpMs (0/-1/NaN/Infinity/fractional) is REFUSED (resource_limit), never expanded to the reference default"*).

**Realization (rev30 — ONE canon-transparent input boundary + its coverage control).** The boundary rests on ONE
primitive: `admitDeep` is BYTE-TRANSPARENT to canon — for every `x`, either it REJECTS `x` (fail-closed, never looser
than canon) or it accepts and `canon(admitDeep(x))` behaves identically to `canon(x)` (both throw, or byte-for-byte
equal). So the door snapshot can NEVER make an input verify differently or more permissively; a self-audit found and
closed an earlier depth-64 cap that FALSE-REJECTED a valid deep doc canon accepts, and a function-DROP that accepted an
input canon rejects (*"CANON-TRANSPARENT: admitDeep is byte-transparent to canon (never looser; byte-identical when accepted) — the input-boundary soundness linchpin"*). Every UNTRUSTED public entry admits its input ONCE at its door
(`verify`/`verifyAsync` split into a public door + `verifyCore` so the internal identity coupling is not re-cloned;
`resolveByDiscovery` admits before the discovery `shard` is read), and a from-CODE control — the input-boundary grid —
asserts each exported verifier admits its input, so coverage is answered in CI, not from memory
(*"BOUNDARY-GRID: every exported verifier admits its input once (no TOCTOU re-read across the surface — coverage answered in CI, not from memory)"*).

**Realization (rev31 — the boundary proven, not asserted).** A round-28 audit disproved the rev30 canon-transparency
claim three ways; each is now closed at the primitive and PROVEN by a test rather than a hand-enumerated corpus.
`admitDeep` traverses EXACTLY canon's domain — `Object.keys` (enumerable own STRING names, INCLUDING `__proto__`/
`constructor`/`prototype` as own data, so the exact-key grammar REJECTS an extra member instead of the old silent DROP
that produced a false VALID), non-enumerable keys and symbols excluded like canon, array HOLES preserved like canon's
`.map`, and non-plain prototypes rejected (fail-closed). A **differential FUZZ** over thousands of random inputs asserts
`admitDeep` is never looser than canon and byte-identical when it accepts (*"CANON-TRANSPARENT FUZZ: 3000 random inputs (pollution names / non-enumerable / sparse / non-plain proto / deep) — admitDeep is never looser than canon and byte-identical when accepted"*). Coverage is answered FROM code by PARTITION, not a name regex (a self-audit caught the first
attempt filtering exports by `/^(verify|resolve|…)/`, which SILENTLY dropped real consumer entries like
`checkAuthorityProof`): every function export is classified FROM the module exports as consumer-surface (untrusted wire
input → must be total) or exempt-with-reason, and a new export fails until classified (*"FROM-CODE PARTITION: every function export is classified surface|exempt (no silent drop — a new export fails until classified)"*); then every
consumer-surface export returns a structured result — never a host throw — on a hostile-fixture BATTERY (throwing-trap Proxy, revoked Proxy, throwing-index array-like) in any argument position
(*"FROM-CODE TOTALITY (hostile BATTERY): every consumer-surface export returns structured, never a host throw, on EACH escape shape (throwing-trap Proxy, REVOKED Proxy, throwing-index array-like) in any argument position — the fixture is exhaustive, so a new non-total path fails HERE (round-51)"*). And the lockstep gate now verifies each
registered adversarial check against the EXECUTED-check manifest conformance emits, so a disabled/renamed check no longer
passes on source-substring presence. The input-boundary grid AWAITS each verifier to settlement before counting getter
reads (a synchronous read-count would see only the reads before the first await; an async verifier that re-read a caller
field AFTER an await would slip it), proven by a negative control that reads its input, awaits, then re-reads and is
OBSERVED as two reads (*"BOUNDARY-GRID async-aware: a verifier that re-reads its input AFTER an await is OBSERVED as read-count 2 (the grid awaits settlement; a sync snapshot would miss it) — round-29 div1"*).

**Realization (rev32 — the controller invariant: single admission, non-bypass output).** A round-29 audit showed the
rev30/31 target was WRONG. "`admitDeep` byte-transparent to canon" tries to make the admission a faithful MIRROR of the
raw input `x`, so that a downstream reader may consult EITHER `x` or the snapshot `x̂`. For a stateful `Proxy` a faithful
mirror is IMPOSSIBLE: `canon` reads a value through `[[Get]]` (`v[k]`) while `admitDeep` read it through the DESCRIPTOR
(`getOwnPropertyDescriptor(v,k).value`), and a Proxy returns one value to the descriptor (the signed `state`) and another
to `[[Get]]` (a tampered `state`). `verify` then vouched for the descriptor face while the consumer's `contentHash(x)`
addressed the `[[Get]]` face — a false `VALID` for data the consumer never had. The soundness linchpin is therefore NOT
mirror-fidelity but a **non-bypass** rule: the verifier is a CONTROLLER with three stages —
(**R1**) admission `𝒜` reads `x` through ONE channel ONCE into an inert frozen `x̂`, or rejects; after `𝒜`, `x` is DEAD;
(**R2**) verification is a total function of `x̂` and the verifier's OWN faculties `(ℐ_v, ρ_v)`;
(**R3**) EVERY emitted quantity — the verdict, the identity `id(x̂)`, the handle, the served-list basis — is a projection
of the processing over `x̂`, and NO emitted quantity re-reads `x`. Under R3 the mirror's fidelity is irrelevant, because
`x` is never read after `𝒜`. Realized two ways: `admitDeep` snapshots each value through canon's OWN channel (`v[k]`,
`[[Get]]`) — the exact face `canon`/`contentHash` read — so a Proxy's tampered `[[Get]]` face is what gets verified and
FAILS the signature (*"R3 NON-BYPASS: a stateful Proxy answering the descriptor one value and [[Get]] another → INVALID, not a false VALID — verify reads the SAME face canon/identity reads"*); and `verify` EMITS `id(x̂)`, the content hash of
the admitted snapshot, so a consumer addresses the transcript by the RETURNED id, never by re-hashing a mutable object
(*"R3 IDENTITY: verify emits id(x̂) bound to the admitted snapshot it verified — the transcript is addressed by the returned id, not by a re-read of the raw input"*). "byte-transparent to canon" is retained only as core hygiene (the
admission reads through canon's channels), no longer as the load-bearing claim. A real declared accessor is still rejected
at its descriptor (the round-26 TOCTOU closure holds); a Proxy that hides behind a data descriptor no longer wins because
its `[[Get]]` face — not the descriptor face — is the one admitted and verified.

**Realization (rev33 — R4: the verifier's faculties are its own, never caller-supplied).** F.9 places every verifier in the
PAIR `(ℐ_v, ρ_v)`: the resource budget `ρ_v` (its time coordinate `T_v` among them) belongs to the VERIFIER, not the
request. A round-29 audit showed the code violated this: the witness-budget clock was exposed as a public `opts.__nowMs`
field, so a caller could pass a NON-MONOTONIC clock through the DATA PATH (`verify`/`resolveByDiscovery` opts) that rewinds
the deadline, expands the effective leaf timeout, lets a slow connector return a final receipt, and flips
`INDETERMINATE(resource_limit)` into a served-list `VALID:HIGH` (reproduced on live code — the "self-limits, mints no
trust" claim was false). The controller rule R4: the input may carry only a formalized POLICY that TIGHTENS `ρ_v` (the
scalar `maxWitnessOpMs`, which only lowers the budget), never the MECHANISM of measurement. The clock now lives in an
INTERNAL module outside the package's public API — a wire caller passing a document cannot reach it — is monotone-guarded
(a backward source is clamped so it can never grant more time than a forward clock), and the per-leaf timeout is bounded
independently of it. A hostile `__nowMs` in the public opts is DEAD (*"R4 CLOCK-OWNED: a hostile __nowMs in public opts is DEAD (never read) — it cannot expand the witness budget or flip resource_limit into a served-list HIGH (round-29 P0-02; ρ_v belongs to the verifier)"*). The conformance harness drives the clock deterministically through that same internal
module (a code-level test capability, not a data-path surface), which also retires the wall-clock CI flake at its root.

**Realization (rev34 — R1/R2 self-verification: the gates that PROVE the controller are themselves machine-grounded).**
A round-29 audit showed the GATES proving R1 (admission is total) and R2 (processing only emits what registered checks
enforce) rested on unsound proxies — the controller discipline was violated at the META level, where the gate trusted its
own un-formalized input. (P1-01) the totality sweep fed a hostile Proxy using `fn.length` for the arity and `{}` for the
other arguments; `fn.length` stops at the first default parameter (`resolveCadence.length === 1` though it takes four
args, so the 4th was never tested) and `{}` short-circuits a verifier before it reads the hostile position (`verifyAnchor`
returns early on a malformed proof, never reaching the `contentHash` read) — so "hostile in ANY argument position" was
never actually exercised, and `resolveCadence(_,_,_,hostile)` / `verifyAnchor(hostile, validProof)` threw host exceptions.
Fixed with a machine SIGNATURE REGISTRY: the real arity plus a VALID-SHAPED reachability fixture per position, so the
Proxy is actually REACHED with the other args valid, and every surface export must be declared or the from-code check
fails (*"FROM-CODE SIGNATURE REGISTRY: every consumer-surface export has a declared signature (real arity + a valid reachability fixture per position) — no surface export escapes the totality sweep, a new one fails until declared"*); the two
gaps are now total at their door, and `witnessNoFork` — exported, taking an untrusted endpoint body, its verdict gating
the served-list basis — is reclassified CONSUMER SURFACE and made total (adjudication div1, adopted). (P1-02) the
lockstep gate trusted a committed manifest without binding it to the code it describes, so a disabled check with an
un-regenerated manifest passed. Fixed by making the manifest EVIDENCE content-bound to its source — it carries the sha256
of `conformance.mjs` and `index.mjs`, and the gate recomputes and rejects a stale manifest, exactly as a UST receipt is
content-bound to the state it attests (*"SOURCE-BOUND MANIFEST: the executed-check manifest carries the sha256 of conformance.mjs and index.mjs — the lockstep gate recomputes them and rejects a stale manifest (evidence content-bound to its source, not trusted by CI order)"*). The principle: a gate that proves a controller rule must MACHINE-VERIFY it
self-containedly — reach the real code path, bind evidence to its source — never trust a heuristic or a detached artifact.

**Realization (rev35 — R3 spans the whole controller, not just `verify`).** A round-30 audit showed the rev32 R3 fix was
INCOMPLETE: it closed `verify`'s own path (admit through canon's channel, emit `id(x̂)`), but the RESOLVERS — which are
themselves verifier operations — call `verify(x)` and then RE-READ the raw `x`. `resolveKeys` called `verify(genesis)` then
read `genesis.state`/`genesis.sig`/`contentHash(genesis)` off the original object (eight raw reads); the provenance walk
called `verify(refDoc)` then recursed through raw `refDoc.state`. A stateful `Proxy` showed the SIGNED face to the admission
and a DIFFERENT signed face to the re-reads, so `resolveKeys` emitted keys for a genesis `verify` never vouched for, and a
missing nested referent was falsely reported `verified` — R3 broken INSIDE the controller. R3 is a property of the ENTIRE
controller: every resolver admits its untrusted input ONCE at its own door and operates only on the frozen snapshot (the
reducer's genesis and each resolved referent are `admitDeep`'d once; `verify` re-admits the frozen snapshot idempotently;
every downstream read and recursion is over that snapshot). Machine-checked by extending the input-boundary grid to the
resolver surface — a resolver that re-reads a raw signed field fires the read-counting getter ≥2 (`resolveKeys` read `state`
8× before the fix) — and by an adversarial closure (*"R3 RESOLVER: resolveKeys admits its genesis ONCE — a two-face Proxy (signed A to verify, tampered B to the reducer) emits keys for the VERIFIED face or errors, NEVER the re-read face"*). The
lesson: a controller rule realized only at the obvious entry (`verify`) is not realized; it must hold at every operation
that touches untrusted input.

**Realization (rev36 — R4's faculty is a monotonic ELAPSED clock, not a wall clock behind a wrapper).** A round-30 audit
showed the rev33 R4 realization was still wrong at the FACULTY. The whole-op witness budget was measured with `Date.now()`
behind a non-decreasing WRAPPER that clamped a backward step to its last value. F.9 forbids exactly this: a wall-clock value
with a monotone wrapper. On a backward step — an NTP correction on a real wall clock jumping forward then back, or a test
rollback — the wrapper FROZE time at `_last`, so the operation deadline was never reached, the aggregate `ρ_v.time` budget
DISAPPEARED, and a slow connector confirmed a served-list HIGH that a forward clock would have refused. The fix is not a
better wrapper but the RIGHT source: `performance.now()` — a MONOTONIC elapsed-time clock (milliseconds since an arbitrary
epoch, non-decreasing by construction, immune to wall-clock/NTP correction). It cannot go backward, so it needs no wrapper
and cannot freeze; the budget is elapsed against an operation-local start, never a `Date.now()` deadline (and every
deadline comparison across the witness/substrate path is on this one monotonic scale — mixing it with `Date.now()` was its
own bug). Machine-checked: the production clock is non-decreasing across reads (*"R4 MONOTONIC: the witness budget clock is a monotonic ELAPSED source (performance.now), non-decreasing across reads — a wall-clock/NTP rollback cannot rewind the deadline and disable the whole-op budget (round-30 P1-01; not a wall clock with a wrapper)"*).

**Realization (rev37 — R2's proof of execution is observed IN-PROCESS, not read from a forgeable artifact).** A round-30
audit showed the rev34 R2 fix was still insufficient. Binding the executed-check manifest to `sha256(conformance.mjs)` +
`sha256(index.mjs)` proved which source the manifest CLAIMS to describe, but the manifest's `checks` array is caller-authored
data: an attacker who DISABLES a registered adversarial check, RECOMPUTES the two source hashes, and keeps the old `checks`
array produces a fresh-looking, internally-consistent manifest that the standalone gate accepts — no evidence the
conformance process ever ran it or that it passed. A committed artifact can never be its own proof of execution. The fix:
the lockstep validation runs in the SAME process that ran the checks, over the IN-MEMORY executed set — a disabled
registered check is simply ABSENT from that set, so the run hard-fails and exits non-zero; the committed manifest is kept
only as a human-readable / drift artifact, no longer the proof. Machine-checked by the enforcement itself plus an
adversarial closure that a registered check dropped from the executed set is detected (*"LOCKSTEP IN-PROCESS: a disabled registered check is CAUGHT in-process — the lockstep validation over the LIVE executed set flags any registered adversarial-closure check absent from THIS run (never a committed, forgeable manifest; round-30 P1-02)"*). This completes the R2 lesson from
rev34: a gate that proves execution must OBSERVE the execution, not trust an artifact that merely names it.

**Realization (rev38 — R3 spans the NESTED input graph; and the honest bound on the R2 self-proof).** A round-31 audit
showed R3 was STILL realized only at the obvious point: rev35 admitted the PRIMARY argument of each resolver, but the
untrusted DATA objects NESTED in `opts`/`config` stayed live. `admitOpts` is a SHALLOW admission — it preserves function
capabilities (`fetchImpl`, `substrateVerify`, `inclusionVerify`) and copies top-level keys, but does NOT deep-admit a nested `opts.genesis` /
`config.checkpoint` / a `chain`. So `resolveAuthority` verified `genesis` via `resolveKeys` (which admits its own snapshot)
then RE-READ the raw nested genesis for `contentHash` and capacity; `verifyStream` verified `checkpoint` then re-read its
raw class/head; `deriveCheckpointFreshness` verified the chain then re-read raw `chain[last].body` for scope/sequence. A
two-face Proxy served the signed face to the inner verify and an unsigned face (elevated capacity, a wrong sequence, a fake
active genesis) to the outer reads — three false `VALID:HIGH`/corroborated outputs. Fix: EVERY untrusted DATA object a
resolver verifies is DEEP-admitted ONCE and read only from the frozen snapshot, whether it is the primary argument or
nested in `opts`/`config`; the read-count grid now covers the nested positions (*"R3 NESTED: a two-face NESTED genesis in a resolver opts/config graph → the output is a projection over the VERIFIED face, never the unsigned re-read (round-31 P0-01/02/03; admitOpts is shallow, nested untrusted docs are deep-admitted once)"*).

The same audit corrected an OVERCLAIM in rev37: the in-process lockstep enforcement over the live executed set closes the
stale/forged-MANIFEST defect (it proves a registered check RAN and returned truthy in-process), but it does NOT prove the
check's ADVERSARIAL SEMANTICS — a maintainer who, in the SAME commit, weakens a registered `check(id, …)` to `check(id, true)`
keeps the label present and the enforcement green. Label membership is a drift/consistency control, not a cryptographic
proof of test quality. The SEMANTIC trust root is NOT the byte-vectors themselves (round-32 P1-01, conceded): they are
generated from THIS implementation and drift-gated by regenerate==committed, so a same-commit maintainer who changes the
impl AND regenerates the expected results keeps the gate green — the corpus proves cross-implementation CONSISTENCY and
portability, not correctness. The byte-vectors are therefore a VERSIONED, EXTERNALLY-PINNABLE conformance/regression
oracle, not a self-authenticating authority. The semantic root proper is the reviewed normative specification, at least
one INDEPENDENTLY-authored implementation that passes the unchanged corpus, externally-pinned release-signed vector
digests, and human cryptographic review (still pending). The model claims only what each layer proves. (round-31 P2-01: a signature-registry fixture
(`verifyKeylogTerminality`) whose first argument was a domain string short-circuited before the hostile position — replaced
with a real key-log head record so every declared position is actually reached.)

**Realization (rev39 — the nested-input class is closed at ONE control, not per resolver).** rev38 deep-admitted the
nested doc of the THREE resolvers the audit named, but a self-sweep found the same shape (`admitOpts` is shallow → a nested
untrusted DATA object in `opts`/`config` survives) in ~eight resolvers. Point-fixing the found instances is the recurring
failure — a rule realized at the reported sites but not across the surface. The class is instead closed at its ONE
boundary: **`admitOpts` now DEEP-admits every nested value** (a function stays a capability; a verifier-MINTED branded token
— anchor/served/fresh/handle, which a caller cannot forge — is passed through by `admitDeep`; every other nested object or
array is frozen inert). No resolver — patched or not, present or future — can hold a live nested caller object to re-read
after verification. Machine-checked on a resolver that was NEVER individually patched (*"R3 ONE-CONTROL: admitOpts deep-admits EVERY nested opts/config DATA value once, so a resolver NOT individually patched (verifyEpochTransition) reads its nested doc ≤1 and cannot be shown a second face — the whole nested-doc re-read class is closed at ONE boundary (round-31)"*), and the read-count grid now covers seven nested positions across the resolver surface. This is the concrete
form of the controller lesson: close the CLASS at one control, do not chase its instances.

**Realization (rev40 — the public evidence-order path is the SAME closed decode as the kernel; and the Horn trace agrees
with the canonical projection).** A round-32 audit found that the temporal-order predicate had TWO decoders. The reference
KERNEL (`checkAuthorityProof`, the independent second derivation) types evidence facts through a CLOSED per-proof-kind ADT
(`FACTS_SCHEMA`/`ORDER_COORD`/`orderSemantic`): a position coordinate is read only from the kind's authorised fields
(`pow-header-chain`→substrate/position, `transparency-log`→log_id/index), namespaced by the trusted proof_kind; a
`rfc3161-tsa` is a SAME-CLOCK pair of REAL calendar instants with not_before ≤ not_after. But the PUBLIC path
(`deriveCheckpointFreshness → compareEvidenceOrder`) never applied that decode — it read generic `substrate`/`position`/
`not_before`/`not_after` off whatever facts were present. So a connector receipt could wear another kind's ordering facts
(a `transparency-log` carrying `{substrate, position}`), a lexicographically-maximal NON-calendar string
(`9999-99-99T99:99:99Z`, shape-valid), an INVERTED interval, or a CROSS-CLOCK pair — and mint `proven-after`, lifting the
corroborated-freshness rung. Fix: the public `compareEvidenceOrder` now mirrors the kernel's decode EXACTLY (same closed
kind set, same coordinate fields, `isRealRfc3339Z` = the kernel's `pRFC`, same proof-kind/clock namespacing), so the two
INDEPENDENT derivations agree; the kernel in turn does its own inline magnitude compare and no longer delegates its order
verdict to the producer (*"R32 order cross-kind: transparency-log wearing pow facts {substrate,position} → unproven (its coord is log_id/index)"*). The same audit found the Horn explanatory trace internally contradicted the canonical
`projectTier`: `provePredicates` mapped a `pinned` identity (below the HIGH threshold) to `name-bound`, so the trace
derived `TierHIGH` while `projectTier` returned `LIGHT`. Fix: `pinned` maps to a `key-pinned` atom that lifts no Tier
rule, and a grid check pins every derived `Tier*` to `projectTier` over the whole identity×time lattice (*"R32 Horn≡projectTier: every identity×time cell — max Horn Tier == projectTier"*). (round-32 P1-01, conceded: the byte-vectors
are a portability oracle, not the semantic root — see rev38's corrected R2 bound above.)

**Realization (rev41 — the public receipt ADMISSION applies the kernel's closed typed ADT; and issuer_id is read from the
admitted snapshot, not the raw receipt).** rev40 mirrored the kernel only at the ORDER COORDINATE (`decodeOrderFacts`),
but a round-33 audit showed the FULL public-vs-kernel evidence judgment still SPLIT: `verifyEvidenceReceipt` validated the
receipt loosely — `facts` merely "an object" (extra signed fields allowed), `issued_at` only `RFC3339Z.test` (the SHAPE,
so `9999-99-99T99:99:99Z` passed), no registered-`proof_kind` check, no exact per-kind facts. So a receipt the KERNEL
rejects (`decodeRec(FACTS_SCHEMA[kind])` / `bad:issued_at`) was accepted publicly and minted a BRANDED VerifiedEvidence
handle → corroborated freshness. A VerifiedEvidence brand is a capability certificate for the WHOLE receipt, not only
the two order fields one consumer reads, so consumer-side typing cannot repair it — admission typing is REQUIRED
(round-33 divergence_2, conceded). Fix (P0-01): `verifyEvidenceReceipt` applies the SAME CLOSED TYPED ADT the kernel's
`closedReceipt` does — exact envelope `{ claim, issuer_id, sig }`, typed sig wrapper, exact+typed claim (real-calendar
`issued_at` via `isRealRfc3339Z` = `pRFC`), registered `proof_kind`, exact per-kind facts — so a kernel-invalid receipt
mints no handle (*"R33 P0-01 signed transparency-log receipt with an EXTRA facts field → INVALID (closed per-kind facts, kernel-aligned)"*). And (P0-02) the seam re-read the RAW `receipt.issuer_id` after admission — an R3 violation a two-face
Proxy split (a foreign issuer on the `admitDeep` read, the correct connector key on the raw re-read). Fix: read
`R.issuer_id` from the admitted snapshot; a whole-surface sweep confirmed every other `admitDeep` site reassigns its
argument to the admitted value, so the raw-re-read class is closed at this one residual (*"R33 P0-02 issuer_id two-face Proxy → INVALID; issuer_id read from the ADMITTED snapshot R, never a raw re-read"*). Both divergences were overturned; the
public seam is now the kernel's closed decode at admission, and every emitted handle is a projection over the inert snapshot.

**Realization (rev42 — the closed-ADT-at-admission class, SWEPT across every signed authority witness).** rev41 closed the
class for evidence receipts and I posed the sweep as a divergence — "does the same class remain open for
authority checkpoint/genesis/epoch/uniqueness?" — instead of sweeping it. A round-34 audit answered **P0=4**: the class was open
across ALL of them. (1) `resolveCheckpointRoots` / `authorityCheckpointSigOk` / `verifyAuthorityCheckpointChain` checked
only `keyId(pub) === key_id`, never strict Pub32 — and Node's base64url decoder maps a non-canonical trailing-bit alias
(`…YKc`→`…YKd`) to the same 32 bytes, so a genesis / authority checkpoint carrying the alias rooted a branded authority the kernel
`strictPub` rejects. (2) `verifyAuthorityCheckpointChain` closed the body but not the sig envelope, so an unsigned
`sig.extra` shifted the `authorityCheckpointId` (which hashes `{body, sig}`) and minted a chain pin. (3)
`verifyCheckpointUniqueness` accepted an `as_of` / extra-field claim and an `alg:"RSA"` sig wrapper the kernel `VOTE_CLAIM`
/ `SIG_ENV` reject. (4) `verifyEpochTransition` / `verifyCheckpointRecovery` accepted open records + untyped sig wrappers
the kernel `closedTransition` rejects. Fix: the public authority verifiers apply the SAME closed typed ADT the kernel
does to EVERY signed witness — a shared strict `Pub32` at every authority-bearing public field, and
`closedCheckpointWitness` / `closedTransitionWitness` / `closedVoteWitness` / `closedRecoveryWitness` (mirroring the
kernel `closedCheckpoint`/`closedTransition` + `SIG_ENV` + `CHECKPOINT_BODY`/`TRANSITION_CLAIM`/`VOTE_CLAIM`) BEFORE any
`keyId`/verify/id/mint — so a witness the kernel rejects roots/mints nothing (*"R34 P0-02 an authority checkpoint witness with an unsigned EXTRA sig field → INVALID (closed { body, sig } — no checkpoint-id malleability)"*). The `checkpointUniquenessClaim`
builder was aligned to the kernel `VOTE_CLAIM` (no self-declared `as_of` / `observed_map_root`); with a closed claim +
binding, every admitted uniqueness attestation for one authority checkpoint is byte-identical, so a uniqueness quorum cannot split
— conflict is real only where the payload can differ (checkpoint-recovery). The controller lesson, again: when I SEE the class
extends (and name the siblings in a divergence), I owe the SWEEP in that rev — not a question.

**Realization (rev43 — the signer-admission class closed at ONE primitive (`admitSigner`), not per witness).** rev42 swept
the closed-ADT across the witnesses but hand-mirrored each sig wrapper, and the hand-work left the SAME sub-check out at
three sites: `verifyCheckpointUniqueness`, `verifyCheckpointRecovery` and `verifyNoForkEvidence` bound `keyId(pub) ===
issuer_id` but never bound `sig.key_id` — so a witness carrying a FOREIGN `sig.key_id` (or, for no-fork, `alg:"RSA"` + an
open wrapper/envelope) was admitted publicly and minted the strong coordinate (`attested` / a checkpoint-recovery `ChainHandle` /
`authoritative` → `VALID:HIGH`), while the kernel binds `sig.key_id === issuer_id === keyId(pub)` and rejects it. The
audit's recommendation and the meta-lesson agree: **do not repair the sites independently — introduce ONE shared
signer-admission primitive** and route EVERY signed authority witness through it. Fix: `admitSigner(sig, expectedKeyId)`
succeeds iff the wrapper is an EXACT Ed25519 `{ alg, key_id, pub, sig }` with `expectedKeyId === sig.key_id ===
keyId(pub)` and canonical Pub32/Sig64; it returns the pub. Receipt, checkpoint, transition, uniqueness, checkpoint-recovery AND
no-fork all consume it BEFORE grouping / identity / verdict / mint — no-fork is now inside the closed-ADT sweep with an
exact envelope + typed claim (*"R35 P0-01 uniqueness sig.key_id ≠ issuer (admitSigner binds issuer===key_id===keyId(pub)) → NOT attested"*). A machine-check gate asserts the choke-point rejects EVERY sig-wrapper tampering class, so a wrapper
divergence cannot ship (*"R35 admitSigner gate: every sig-wrapper tampering on a genuine attestation → NOT attested; only the genuine wrapper passes"*). The checkpoint-recovery `reason` (rev42) was removed from the signed claim (P1-01) — the normative
checkpoint-recovery tuple is `(domain, genesis_epoch, last_accepted, effective_sequence, replacement_authority)`; a human annotation
is not part of the signed authority claim. Meta: across rounds the audit P0 count ran 1→2→4→3; the fix that finally
converges is a single choke-point + a gate, not another hand-mirror.

**Realization (rev45 — the nested authority KEY-PAIR admission at ONE primitive, and canonical wire at the crypto LEAF —
the first 0-P0 round).** rev43 closed the SIGNER wrapper at `admitSigner`, but the audit found the SAME shape one level
down: a `{ key_id, pub }` authority PAIR was typed as two INDEPENDENT strings (`key_id` a hash, `pub` a Pub32) with no
identity RELATION, so when both checkpoint-recovery signers agreed on a CONTRADICTORY pair (`key_id` of A, `pub` of B) the quorum
carried it and `verifyCheckpointRecovery` returned a usable-looking authority with `key_id ≠ keyId(pub)` (P1, not P0:
the built-in chain verifier then fails closed because no key can sign against the contradictory pair without a hash
collision). Fix, the same shape as admitSigner: **`admitAuthorityKey({ key_id, pub })`** succeeds iff it is an EXACT pair,
`pub` is canonical Pub32, and `key_id === keyId(pub)`; EVERY authority pair — checkpoint-recovery replacement, transition
destination, genesis authority, pinned prior, authority checkpoint rotation, and each genesis checkpoint-recovery key — routes through it
(*"R36 P1-01 admitAuthorityKey rejects a contradictory { key_id of A, pub of B } pair (via transition destination) — usable only if key_id === keyId(pub)"*). Separately, `edVerifyStrict` was MISNAMED: it delegated the sig bytes to Node's
permissive base64url decoder, so the provenance `src_sig` path (outside the authority-witness class) authenticated a
non-canonical alias that a strict implementation rejects — a raw-wire agreement split. Fix at the crypto LEAF, not the
call site: `edVerifyStrict` now requires canonical Pub32/Sig64 before verifying, so a non-canonical alias never verifies
and EVERY caller (present or future) is canonical-safe with no per-site guard (*"R36 P1-02 edVerifyStrict REJECTS a non-canonical Sig64 alias (same 64 bytes, different wire) — canonical enforced at the crypto leaf"*). The vacuous P2 regression
vector (one malformed + one genuine statement → quorum-not-met for the WRONG reason) was replaced by a threshold-complete
malformed quorum that exercises the actual property. Round-36 was the FIRST **0-P0** round (P0 count 1→2→4→3→0): the
class converges when each recurring shape is closed at a single primitive (`admitSigner`, `admitAuthorityKey`) or the
leaf, with a machine-check gate, rather than hand-mirrored per site.

**Realization (rev46 — R1 (admit the input) UNIFIED at every exported operation: the last two un-admitted inputs were a
Merkle co-path and the lattice operands).** The authority primitives held (round-37 divergence_1 conceded), but the audit
found the SAME controller rule — **R1: admission reads x into an inert typed value or REJECTS, totally** — was NOT applied
at two exported ops one level below the authority surface. (P0-01) `verifyKeylogTerminality` and
`verifyCheckpointMapUniqueness` checked only that `siblings` was an array of the right length, then built node preimages
with JavaScript `+`: a `[]` sibling coerced to `''` computed a root under a NON-protocol grammar (so a malformed witness
minted `corroborated` / experimental `attested` freshness), and a null-proto object threw a host `TypeError` (a totality
break) — while the kernel already types its co-paths (`pHashArr`), a public↔kernel split. (P1-01) `joinAssurance` /
`meetAssurance` / `assuranceLE` compared RAW per-axis ranks, bypassing `assuranceState` (the domain admission that
`projectTier` already uses): an out-of-domain axis has rank −1, so the other operand's value silently replaced it and a
`join` SYNTHESIZED a valid-looking `TOP`. Fix, the same shape as every prior primitive: **`admitHashPath(siblings, len)`**
admits a co-path only if it is a length-`len` array of canonical sha256 hashes, and node preimages are built from admitted
hash strings (both Merkle verifiers route through it, matching the kernel) (*"R37 P0-01 a GENUINE key-log terminality proof is still terminal (no over-reject)"*); and every exported lattice op ADMITS both operands with `assuranceState`
before comparing, so an out-of-domain operand yields ⊥, never a synthesized state (rev48 made this total-by-RETURN — see below) (*"R37/R39 joinAssurance with an OUT-OF-DOMAIN operand → RETURNS the valid operand (⊥ contributes nothing, never synthesizes strength from garbage), never a throw"*). A whole-surface sweep confirmed this was the
LAST gap: every exported verifier and algebra op now routes its untrusted structured input through ONE admission primitive
(`admitDeep`, `admitOpts`, `admitSigner`, `admitAuthorityKey`, `admitHashPath`, `assuranceState`, `decodeExact`) before
processing — R1 is uniform between input and output at every level, which is the invariant the recurring findings were
tracing toward all along.

**Realization (rev47 — R1/R3/R4 made uniform at the last three exported ops: a two-read admission, un-admitted algebra
operands, and a caller-expandable resource ceiling).** rev46 claimed R1 uniform, but the audit found the SAME three
controller rules still broken one level below — the deeper the frame is applied, the more the residual shifts from R1 to
R3 and R4. (P1-01, R1/R3) `assuranceState` read each axis `s[ax]` TWICE — once for the rank check, once for the output
copy — so a two-face Proxy passed a weak face to the check and emitted a strong one, and `projectTier` returned a false
`TOP` from a value it never validated. Fix: admit `s` ONCE with `admitDeep` (total — a hostile getter is a coded
`E-ASSURANCE`, never a host throw) and read each axis ONCE from the frozen snapshot (*"R38 P1-01 (R1/R3) assuranceState on a two-face Proxy emits the ADMITTED (first) face, not a stronger re-read"*). (P1-02, R1) the exported evidence algebra
`quorumTrustDomains` (iterated the raw `list`) and `compareEvidenceOrder` (admitted neither operand) were classified
`primitive` and escaped the whole-surface sweep — a hostile Proxy threw a host exception. Fix: admit each operand with
`admitDeep` (fail-closed to `count:0` / `unproven`) and RECLASSIFY both as consumer surfaces in the from-code totality
registry, so the sweep now covers them. (P1-03, R4) `verifyJson`'s `maxInputBytes` was `Number(opts.maxInputBytes ?? …)`
with no clamp — a caller passing `Infinity` EXPANDED the verifier-owned 64 MiB ceiling and turned a resource refusal into
a full verification. Fix: **`admitBudget(supplied, reference)`** — a caller resource scalar may only TIGHTEN
(`min(reference, supplied)` for a finite positive integer; `Infinity`/`NaN`/≤0 → refused), applied at `maxInputBytes` AND
at a sibling the round-38 sweep found the auditor missed (`refBudget`, the referent-walk node budget) (*"R38 P1-03 (R4) verifyJson maxInputBytes:Infinity → structured E-MALFORMED, never an expanded ceiling"*). The controller frame is now
uniform in all four rules across the exported surface: every op admits its input ONCE (R1), computes over the admitted
snapshot + its own faculties (R2), emits only projections of that snapshot (R3), and lets caller policy only TIGHTEN a
verifier-owned faculty (R4).

**Realization (rev48 — the assurance lattice made a TOTAL function (a door that RETURNS, not throws), and the R4 budget
made uniform by removing the `?? default` footgun).** rev47 claimed the frame uniform, but the audit found the SAME two
rules realized as HALF-measures one level below. (P1-01, R4) the round-38 `admitBudget` correctly RETURNS `null` on a
refused budget — but the call site wrote `admitBudget(opts.refBudget, 256) ?? 256`, and `?? 256` converted that refusal
back into the FULL 256-node budget; a sibling, `maxSupportedBytes`, was read raw (`opts.maxSupportedBytes && … Number(…)`)
so `0`/`NaN` (falsy) bypassed the capability check and `Infinity` disabled it. The refusal existed but was SWALLOWED — a
faculty admission is realized only if its `null` FAILS CLOSED, never coalesces to a default. Fix: both scalars route
through `admitBudget` and a `null` returns `E-MALFORMED`.
Cf. *"R39 P1-01 (R4) refBudget:Infinity → E-MALFORMED (a refused budget FAILS CLOSED, never coalesces to the 256-node default)"* and *"R39 P1-01 (R4) maxSupportedBytes:0 → E-MALFORMED, never a falsy-bypass of the capability check"*.
(P1-02, R1) the assurance lattice was still PARTIAL: `assuranceState` (the assurance door) THREW a coded `E-ASSURANCE` on a
malformed operand (rev37/38), so `capAssurance` — which reads an UNTRUSTED consumer `ceiling` — and the exported
`checkBounds` host-threw when reached as consumer surfaces, yet both were classified `primitive` and exempt from the sweep.
A rule realized as a coded THROW at a consumer surface is not realized: the sweep demands a RETURN, and a lattice operation
is mathematically TOTAL (meet = per-axis min, join = per-axis max), so a malformed operand must map to ⊥ and the op must
RETURN, not throw. Fix: the door mirrors the INPUT door — `assuranceState` RETURNS a reject sentinel (like `admitDeep`
→ `ADMIT_REJECT`), never throws; every lattice surface then fails closed by RETURN (`meet` → ⊥, `join` treats the malformed
operand as the ⊥ identity so it never synthesizes strength, `assuranceLE` → `false`, `projectTier` → `NONE`, `capAssurance`
admits its `ceiling` and caps to ⊥); `checkBounds` admits its `doc` at the public door (the internal hot path calls the
private `boundsOf` over the already-admitted snapshot, no re-clone). All are RECLASSIFIED as consumer surfaces and swept.
Cf. *"R39 P1-02 (R1) capAssurance with a HOSTILE consumer ceiling → RETURNS ⊥ (fail-closed cap), never a host throw"* and *"LATTICE (8) missing/out-of-range axis ⇒ reject sentinel (fail-closed, total-by-return) + projectTier ⇒ NONE"*.
The lattice is now a total function into `AssuranceState ∪ {⊥}`, and R1/R4 are realized as RETURNS at every exported surface
— a coded throw at a consumer boundary was the residual the recurring lattice findings (rev37, rev38, rev39) were tracing
toward.

**Realization (rev49 — the SYNC verify door admits `opts` (the last un-admitted public opts input), and `capAssurance`
distinguishes ABSENT from MALFORMED — falsy ≠ absent).** rev48 made the lattice total, but the audit found two R1 admission
gaps one level out. (P1-01, R1) the synchronous `verify(doc, opts)` admitted `doc` but forwarded the LIVE `opts` object to
`verifyCore` — every OTHER public entry (`verifyAsync`, `verifyJson`, `resolveAuthority`, `forkChoice`, `resolveCadence`,
`resolveByDiscovery`) already routed `opts` through `admitOpts`, but the most-used door did not. `verifyCore` reads
`opts.maxSupportedBytes` more than once (compute the budget, then decide to enforce it), so a two-face `opts` Proxy showed a
1-byte capability to the budget and `undefined` to the guard — a verifier-owned resource refusal became `VALID`. Fix:
`verify` admits `opts` at the door with `admitOpts` (functions/capabilities preserved, scalars frozen ONCE) and passes only
the inert snapshot to `verifyCore`, so every `opts` read is consistent — the two-face Proxy's `maxSupportedBytes` trap now
fires zero times (*"R40 P1-01 (R1) sync verify admits opts ONCE — verifyCore never re-reads the live opts Proxy (a two-face maxSupportedBytes trap fires 0×)"*). (P1-02, R1 + F.5.0 gap 2) `capAssurance` guarded the ceiling with `if (!ceiling)
return s` — so a FALSY ceiling (`0`/`''`/`NaN`/`false`) was read as ABSENT and returned the full proven state, and a truthy
NON-record (`1`/`'x'`/`[]`) defaulted every axis to its MAX, both PRESERVING `TOP` where the rule requires ⊥. The footgun is
the same `falsy = absent` conflation that `maxSupportedBytes && …` carried at rev48. Fix: only `undefined`/`null` are absent
(identity); a rejected admission, a non-record (scalar/array), or an out-of-range axis caps to ⊥ (*"R40 P1-02 (R1) every MALFORMED capAssurance ceiling (falsy scalar / non-record / array: false,0,\"\",NaN,[],1,\"x\",true) → ⊥ (projectTier NONE), never a preserved TOP"*). Both findings are the SAME rule R1 realized incompletely: admission must happen at EVERY door
(`opts`, not only `doc`), and an admission guard must distinguish ABSENT (`undefined`/`null`) from MALFORMED (a falsy or
wrong-typed value) — a falsy value is not a missing one.

**Realization (rev50 — "inert" means IMMUTABLE: the admitted `opts` snapshot is FROZEN, and the falsy≠absent guard is swept
to the authority SELECTORS).** rev49 admitted `opts` at every door, but the audit found the admitted snapshot was not
INERT in the strong sense: `admitOpts` returned a null-proto object whose fields were `writable`, WITHOUT `Object.freeze`
(its nested data values were already frozen by `admitDeep`, but the top-level wrapper was not). (P1-01, R1/R3) a preserved
capability function is invoked with that snapshot as `this` (`opts.resolveRef(h)`), so a hostile resolver ran
`this.acceptConsumerOverride = true` — MUTATING the policy DURING verification — and `verifyCore`'s later read of
`acceptConsumerOverride` (the `consumer-override → authoritative` projection) then lifted the tier LIGHT→HIGH. The claimed
"inert frozen `x̂`" was mutable. Fix: `admitOpts` returns `Object.freeze(out)` with read-only fields — the snapshot is now
IMMUTABLE, matching `admitDeep`; a capability `this`-write is a no-op / strict-mode throw (caught fail-closed), and the
tier cannot be flipped (*"R41 P1-01 (R1) the admitted opts snapshot handed to a capability as `this` is FROZEN (inert) — a resolveRef cannot mutate policy (acceptConsumerOverride) to flip LIGHT→HIGH"*). This sharpens R1: **"after 𝒜, `x` is DEAD"
means the admitted value is IMMUTABLE, not merely a copy — a snapshot that can be written during processing is not inert.**
(P1-02, R1 + I4) the falsy≠absent guard (rev49, `capAssurance`) was NOT swept to the authority SELECTORS: `resolveAuthority`
and `verifyCore` guarded `genesis` with `if (!genesis)` / `if (opts.genesis)`, and `admitDeep` accepts a primitive scalar,
so a PRESENT falsy `genesis` (`0`/`''`/`NaN`/`false`) was read as ABSENT → `self-asserted`/`VALID:LIGHT` instead of
`E-GENESIS`; the same shape hid at `pinnedKeys` (a non-array pin set silently dropped the restriction) and in `verifyStream`
(`genesis`/`checkpoint`). Fix: an authority selector treats only `undefined`/`null` as absent; a present non-record is
MALFORMED — `E-GENESIS`/`E-MALFORMED`/`complete:none` (*"R41 P1-02 (R1) resolveAuthority with a PRESENT falsy/scalar/array genesis → E-GENESIS (falsy ≠ absent), never a silent self-asserted"*). The distinction that held: EVIDENCE fields
(`nameMap`/`noForkEvidence`/`servedNoFork`) fail SAFE (present-invalid → no upgrade, by design), but authority SELECTORS
must fail CLOSED (present-malformed → reject) — a selector silently degraded to "no authority" is a totality break, not a
conservative default.

**Realization (rev51 — R3 applies to ARRAY ELEMENTS: the key-log is DEEP-admitted; and the axiom/evidence boundary is a
PROVENANCE gate, not a truthiness one).** rev50 hardened the top-level snapshots, but the audit found R3 was not applied
one level INTO an array. (P0-01, R1/R3) `resolveKeys` deep-admitted its `genesis` but ran the key-log through `admitArray`,
which SHALLOW-copied the array (`out[i] = v[i]`) — every element stayed a LIVE reference. The reducer calls `verify(e)`
(which admits and validates ONE face) and then RE-READS `e.state`/`e.sig`/`contentHash(e)` from the live element, so a
two-face key-log entry showed a SIGNED key B to `verify` and an UNSIGNED key C to the re-reads → `resolveKeys` emitted an
attacker key `C` that no accepted signature authorized (a direct authority-soundness break — the first P0 since rev45). Fix:
`admitArray` DEEP-admits each element (`admitDeep(v[i])`) and freezes the array — the reducer verifies and reads ONE frozen
graph, one face (*"R42 P0-01 (R1/R3) resolveKeys DEEP-admits the key-log — a two-face entry (signed key B / unsigned key C) never authorizes C (structured error OR authorizes only B)"*). **R3 is not just "admit the top-level document" — every
untrusted ARRAY the reducer iterates and re-reads must be deep-admitted; a shallow snapshot of an array of records is not
inert.** (P1-01, F.5a.1) the `consumer-override` channel was entered by truthiness — `if (noForkConfirmed || corroborated ||
servedNoFork)` — so an unminted `servedNoFork:{}` (present-invalid EVIDENCE) crossed into the override channel and, with
`acceptConsumerOverride`, reached HIGH. The evidence/axiom boundary is a PROVENANCE gate: only an explicit boolean AXIOM
(`noForkConfirmed`/`corroborated === true`) may create a consumer-override that `acceptConsumerOverride` can lift; an
unminted `servedNoFork` is a caller LOOK-ALIKE that DIVERTS from `corroborated` (rc35-P0a) but carries `override_liftable:
false` and can never reach authoritative (*"R42 P1-01 (R1) an unminted servedNoFork + acceptConsumerOverride does NOT reach HIGH (override_liftable:false), yet still ≠ corroborated (rc35-P0a)"*). (P1-02, I4) the GRANT policy booleans
(`acceptConsumerOverride`/`noForkConfirmed`/`corroborated`) were read by JS truthiness, so the string `"false"` — truthy —
activated the HIGH override; `admitBool` now accepts only a real boolean (`undefined`/`null` → default, any other present
value → `E-MALFORMED`), and `verifyStream` no longer coalesces a present non-array `keylog` to `[]`. The three are one rule:
**a security decision reads a MEASURED input, never a coerced one — a live array element, a truthy look-alike, and a truthy
non-boolean are all inputs that were used without being admitted.**

**Realization (rev52 — the coerced-input class is closed at a FROM-CODE GATE, not per-site).** rev52 fixes four more
instances of the same two classes — but the point of rev52 is that "fix the instance" was the wrong loop: the
coerced-boolean and falsy-selector classes recurred for FOUR rounds (rev48 `maxSupportedBytes`, rev50 `genesis`/`pinnedKeys`,
rev51 three grant booleans, and now `requirePerFrameValid` (a falsy `0` DISABLED per-frame signature verification and passed
a tampered frame as complete), `allowExperimentalAttested` (a truthy `"false"` ENABLED the withheld experimental rung),
`resolveCadence`'s `keylog` (a present `false` erased a retirement and accepted a change signed by a retired key), and
`verifyAuthorityCheckpointChain`'s `else if (genesis)` (a present `false` fell through to a pinned fallback root)) because
each fix was per-SITE. The structural closure is a REGISTRY + a from-code GATE (conformance): (1) NO authority selector may
use the `Array.isArray(X) ? X : default` coalesce — a present malformed selector is admitted, never silently emptied; (2)
every `require*`/`allow*`/`acceptConsumerOverride` grant boolean in the source is REGISTERED and admitted through `admitBool`
(a wrong-typed value → `E-MALFORMED`), so a NEW grant flag fails the gate until admitted and adversarially probed; (3) the
RESTRICTION booleans (`requireAuthoritative`/`requireFreshKeylog`/`requireAnchored`) are measured too — a coerced `0` must
not silently DROP the caller's policy (*"R43/R44 STRUCTURAL: every require*/allow*/acceptConsumerOverride security-policy boolean in index.mjs + reference-checker.mjs is REGISTERED (a new grant flag fails until admitted + adversarially probed)"*). **The lesson
is meta: a defect CLASS is not closed by fixing its known instances — it is closed by a from-code invariant that FAILS when
a new instance appears. The measured-input rule is now enforced by the gate, not by memory.**

**Realization (rev53 — the PUBLIC adapter must not manufacture what the sole-checker refuses, and it is an admission
boundary).** rev52 closed the coerced-input class at a gate — but the gate scanned only `index.mjs`, and the P0 lived one
file over. (P0-01) `verifyAuthorityBundle` (the public authority adapter, in `reference-checker.mjs`) built the checker
config with `uniqueness_threshold: Number.isInteger(trust.uniqueness_threshold) ? trust.uniqueness_threshold : 2` — so an
ABSENT or MALFORMED consumer threshold was replaced with a MANUFACTURED `2`, and two independent witnesses returned
`VALID`/`witness-attested` under a quorum policy the consumer never selected. The inner `checkAuthorityProof` is explicit
(«no `uniqueness_threshold` configured — quorum fails closed», «never a silent default»); the ADAPTER contradicted the
SOLE-CHECKER. This is the recurring two-derivations-must-agree class at the strongest boundary: a public path may PROJECT
the checker's verdict but must never inject a policy the checker would refuse. Fix: the adapter passes the consumer policy
THROUGH — absent → omitted → the checker's `INDETERMINATE` fail-closed; malformed → passed → the checker's
`E-CONFIG-THRESHOLD` (*"R44 P0-01 verifyAuthorityBundle injects NO threshold DEFAULT — the adapter passes the consumer policy through (no `Number.isInteger(...) ? ... : 2` fallback that manufactures a quorum the sole-checker refuses)"*). (P1-02,
R1/R3) the adapter also read `config.trust.uniqueness_threshold` TWICE off the LIVE nested config (once for
`Number.isInteger`, once for the value), so a two-face getter returned `2` to the check and `1` to the value and upgraded
one witness into a quorum; this byte-checker cannot reach `admitDeep`, so it now takes a one-read inert JSON snapshot of
BOTH graphs (`JSON.parse(JSON.stringify)`, like `forkChoice`) and reads only the snapshot. (P1-01) `verifyAuthorityCheckpointChain`'s `recoveryKeys`/`genesisAuthority` selectors were coalesced (`recoveryKeys || {}`) or
silently overridden, so a present `recoveryKeys:false` erased the genesis-authorized checkpoint-recovery set — now the authority
selectors fail closed on a present non-record; and the from-code gate scans BOTH `index.mjs` and `reference-checker.mjs`,
bans `X || {}` / `X || []` as well as the `Array.isArray(X)?X` coalesce, and covers the checkpoint-recovery/authority selectors. **A
public adapter around a sound kernel is a TCB surface too: it must admit its input once and defer to the kernel's contract,
never re-read the live graph or inject a default the kernel would reject.**

**Realization (rev54 — cross-argument admission ORDER (trusted before untrusted), target-judgment projection, and a
BEHAVIORAL adapter/kernel gate instead of a source regex).** The rev53 fix was still not enough — and the reason is
structural: a from-SOURCE regex gate cannot see a SEMANTIC violation. (P0-01, R1/R3) both object adapters encoded/snapshotted
the UNTRUSTED argument BEFORE the TRUSTED config — `checkAuthorityProof` ran `encodeLive(obj, 'package')` before
`encodeLive(config, 'config')`, and `verifyAuthorityBundle` ran `JSON.stringify(inputs)` before `JSON.stringify(config)` (a
bug I introduced at rev52). A hostile getter / `toJSON` in the untrusted argument therefore executed and MUTATED the
still-live consumer config (adding witnesses/domains, setting `uniqueness_threshold: 1`) BEFORE the config was captured, so
the untrusted proof selected the trust world under which its own proof was checked. Fix: **admit the TRUSTED config to
bytes/snapshot FIRST, then the untrusted proof** — a cross-argument mutation now hits only the already-captured,
now-irrelevant original. This generalizes R1: at a multi-argument boundary, capture the TRUSTED inputs before executing ANY
untrusted-object behavior. (P1-01) `verifyAuthorityBundle` returned a non-`Freshness` judgment as a public `VALID` (a
Genesis-only proof read as success by a generic caller) and normalized a malformed `policy` away with `C?.policy || {}`
instead of deferring to the checker's `E-CONFIG-POLICY`. Fix: success is EXCLUSIVE to a `Freshness` judgment (a Genesis-only
proof → `INDETERMINATE` authority_unresolved), and a present malformed `trust`/`policy` is rejected, matching the sole
checker. (P1-02) the from-source gate stayed green through all of this — a regex cannot model admission order, cross-argument
mutation, target-judgment projection, or adapter/kernel agreement. Fix: a **BEHAVIORAL gate that DRIVES each adapter through
its entrypoint** — a hostile getter in the untrusted argument must not change the config the verdict uses, the adapter's
verdict must AGREE with the sole checker over the same config, and a non-target judgment must not become success.
Cf. *"R45 P0-01 (R1/R3) checkAuthorityProof ISOLATES the trusted config — a hostile package getter cannot inject witnesses/threshold into the config the verdict uses (config encoded BEFORE package; identical config_id + verdict)"* and *"R45 P1-01 verifyAuthorityBundle success is EXCLUSIVE to a Freshness judgment — a Genesis-only proof → INDETERMINATE authority_unresolved, never a public VALID"*. **A defect class whose
invariant is SEMANTIC (order, mutation, agreement) is closed by a BEHAVIORAL from-entrypoint gate, not a source regex — the
regex checks the symptom's spelling, the behavioral gate checks the invariant.**

**Theorem R (the Reduction metatheorem — the verifier is an AUTOMATON over canonical bytes, not a COMPUTER over live objects).**
Every public entry `E(x₁, …, xₙ)` decomposes as `E = A ∘ (ρ₁, …, ρₙ)` where each `ρᵢ` is a TOTAL reduction of argument `xᵢ`
to its canonical form and `A` is a pure automaton over those forms. **Independence of the reductions is NOT free
(round-47 correction — the original claim "each `ρᵢ` is a function of `xᵢ` alone, so ORDER is irrelevant" is FALSE for
multiple live signed arguments; see the Correction below).** It holds EXACTLY at the canonical-BYTES boundary (immutable
strings; `JSON.parse` invokes no caller code) and for a discipline-1 reduction (which executes no caller code). A discipline-2
reduction EXECUTES the `[[Get]]` face, so two or more discipline-2 reductions over LIVE objects are NOT independent —
reducing `xᵢ` can fire a getter that mutates a still-live `xⱼ`. Two admissible reduction disciplines, by whether
the argument is signature-bound:
1. **Unsigned input (a consumer TRUST config / policy):** `ρ` reads DATA descriptors only and REJECTS any accessor
   (getter/setter), function, symbol, non-plain prototype, or cycle. **No caller code (a getter, a `toJSON`) EVER EXECUTES —
   the automaton reads its input as DATA, it never runs it.** (`admitInert`.)
2. **Signed input (a proof / a UST document):** `ρ` reads the `[[Get]]` face — the face the signature/`content_hash` is over
   — EXACTLY ONCE into a frozen snapshot, then INTEGRITY is verified by content-address (a two-face proof fails `id = H(canon)`).
   (`admitDeep` / `encodeLive` + the content-hash check.)
**Corollary (why the boundary bugs collapse — at the byte boundary):** the recurring P0/P1 class — a two-face getter, a
cross-argument mutation, an admission-order dependency, an adapter that re-reads a live field — is impossible AT THE CANONICAL-BYTES
BOUNDARY and for a discipline-1 reduction: an unsigned argument's code never runs (so it cannot mutate a sibling) and byte-strings
are immutable. It is **NOT** impossible for two or more discipline-2 (signed, `[[Get]]`) reductions over LIVE objects — reducing one
signed argument can fire a getter that mutates a still-live sibling signed argument (round-47 P0-01). A signed argument is read
once + hash-checked, but ORDER is NOT free when several live signed arguments coexist. The byte kernel `checkAuthorityProofBytes`
(which held every round: 4007-probe fuzz, 0 false accepts) IS `A`; the object adapters that failed were `E`s that had NOT been
decomposed as `A ∘ ρ`.
**Correction (rev65 — round-47 GPT audit refuted the universal-independence claim; the exact boundary is BYTES).** The audit
(`resolveCadence(genesis, cadenceLog, atTime, opts)`) reduced the signed `genesis` before the signed `cadenceLog`; a getter on
`genesis` emptied the still-live `cadenceLog` before its own reduction, turning `E-KEY` into a successful cadence resolution — so
`ρ_cadenceLog` was **not** a function of `cadenceLog` alone and order was **not** irrelevant. The metatheorem is corrected: the
EXACT sound boundary is CANONICAL BYTES — an entry that is a pure function of immutable byte-strings (as `checkAuthorityProofBytes`
already is). **Realization (rev69 — the bytes-in boundary is now a distinct EXPORT, not an internal step, and the claim is bound to
the mechanism):** `resolveCadenceBytes(genesisBytes, cadenceLogBytes, atTime, keylogBytes)` is a pure function of immutable
byte-strings — order-independent BY CONSTRUCTION (a byte-string cannot mutate a sibling and `JSON.parse` runs no caller code) — and
IS the sound public boundary; `resolveCadence` is a CONVENIENCE object adapter over it (serialize each argument, structural before
self-verifying) documented in-code as NOT the hostile-getter boundary. HONEST scope (correcting the rev65 over-label "migrated to the
bytes boundary"): there is NO fully order-independent multi-live-OBJECT reduction in JS — a getter fires on any traversal — so the
object adapter closes the common object-caller case but the SOLE order-free boundary is bytes-in; a caller needing soundness against a
hostile Proxy passes PRE-SERIALIZED bytes to `resolveCadenceBytes`. `resolveCadence` (rev69) and `resolveKeys` (rev70) now EACH
have a bytes-in export (`resolveCadenceBytes` / `resolveKeysBytes`) — the sound order-free boundary — plus an object adapter; the
two genesis-anchored reducers are the split done, and the remaining multi-argument surfaces follow the same pattern, the object
forms staying for backward-compatibility as honest adapters. (round-47 P0-01, bd UST-5t8.)

**Correction (rev74 — round-48 P0-01: the rev69/70 "order-independent BY CONSTRUCTION (a byte-string cannot mutate a sibling)" claim OUTRAN the mechanism at the byte DOOR).** GPT round-48 refuted it. `resolveKeysBytes`/`resolveCadenceBytes` admitted each argument with `Buffer.from(arg)`, and `Buffer.from` runs an ARRAY-LIKE's indexed GETTERS while copying — so a getter in argument 1 mutated the still-live bytes of argument 2 BEFORE argument 2 was captured (a running repro deleted an independently-supplied revocation and restored a retired key → a VALID verdict flip). "Immutable byte-strings" was the intended DOMAIN, but the door never ENFORCED it — the soundness was assumed of the argument's type, not discharged by the boundary. Fix (structural, single-source): every byte entry now admits through the ONE primitive `snapshotBytes` — accept ONLY an EXACT native `Uint8Array` (a Proxy/subclass/array-like/string is rejected: the intrinsic `byteLength`/`buffer` getters read an internal slot a Proxy lacks → throw), then copy into a fresh immutable buffer with the intrinsic setter, so NO caller code runs and no argument can touch a sibling before capture. `checkAuthorityProofBytes` already admitted here (round-8/9 P0-01); `snapshotBytes` was moved to `index.mjs` and the two resolvers — the entries that BYPASSED it — now share it. ONE door, no drift. The fractal lesson, again: a soundness claim must be discharged by the MECHANISM at the boundary, never assumed of the argument's intended type — the same shape as the rev57 cross-arg order fix and the rev65 Theorem-R correction, now at the byte layer.

**Correction (rev76 — round-49: the rev74 "`snapshotBytes` is the ONE door" claim was INCOMPLETE, and cross-IMPLEMENTATION drift is a second face of the same class).** The un-audited periphery, sent to a diverse model for the first time, refuted two more "it is fine"s. (i) **A second raw-byte boundary bypassed the door.** `verifyJson` measured its transport budget as `rawBytes.byteLength ?? Buffer.from(rawBytes).length` — a CALLER-OVERRIDABLE property; a `Uint8Array` subclass with an own `byteLength` getter returning 1 (intrinsic 2008) bypassed `maxInputBytes` and started verification the §13 contract says it must not. Fix: `verifyJson` now admits through an INTRINSIC-based snapshot (`snapshotBinary` — the broader ArrayBuffer/TypedArray/DataView sibling of `snapshotBytes`, reading length/bytes through the intrinsic getters), and the class was swept (`admitUtf8`/`strictUtf8` no longer fall back to `Uint8Array.from(array-like)`). "The ONE door" is only true once EVERY raw-byte entry is inventoried against it. (ii) **A separate implementation that RE-implements validation drifts LOOSER than the core.** `ust-lite` (zero-dependency by design) checked timestamps with a SHAPE regex (accepting `2026-02-31`) and made `class` optional — so a signed document read `VALID:LIGHT` in lite while the full verifier returned `INVALID`, breaking lite's own "a lite-valid document IS a valid UST document" claim. Fix: lite now applies the real calendar rule (byte-identical to core's `calendarValid`) and requires `class === 'observation'`; and — the structural guard — a DIFFERENTIAL gate asserts `lite VALID ⇒ core VALID` over an adversarial corpus, so a future drift FAILS the gate rather than shipping a false accept. "No drift" between two implementations of one spec must be ENFORCED by a differential, never assumed of a copied validator — the cross-implementation echo of the single-door lesson. Also this round: the Node SSRF guard classified IPv4-mapped IPv6 by DOTTED-decimal spelling only (`::ffff:127.0.0.1`), missing the equal HEX form (`::ffff:7f00:1`); fixed to classify by BYTE RANGE, spelling-independent (round-49 P1-01).

**Correction (rev78 — round-50: every rev76/77 FIX and GUARD had a residual hole of the SAME class it closed; the meta-lesson is that a POINT fix leaves the ROOT generating new instances).** Round-50 attacked the round-49 fixes + the CI trust chain and refuted 4 of 5 "it is complete"s — each a narrower echo of an already-"closed" class. (P0-01) `ust-lite` still false-accepted THREE more signed documents (a public partition carrying a `commit` while displaying an unrelated `value` — "what you see ≠ what is signed"; an encrypted partition with no `enc` block; a raw-Unicode homograph `domain_shard`) because lite RE-implements only PART of the core's LIGHT obligations and the rev77 differential enumerated only date/class. ROOT fix: lite now enforces the §4.4 closed envelope XOR + the §4.3a A-label + the AEAD `enc` schema (byte-identical to core), and the differential ENUMERATES every LIGHT obligation. (P1-01) the SSRF byte-range classifier was still a hand LIST — it missed the local-use NAT64 `64:ff9b:1::/48`; ROOT fix: a special-use PREFIX TABLE (embedded-IPv4 forms classified, every other non-globally-reachable prefix refused). (P1-02) `snapshotBytes`/`snapshotBinary`/`admitUtf8` ran an `instanceof` / `Object.getPrototypeOf` on the untrusted input BEFORE the `try`, so a Proxy's `getPrototypeOf` trap threw a host exception OUT of the "total" door; ROOT fix: every type-probe is now INSIDE the try (intrinsic getters throw without invoking a trap), and the doors are total on a Proxy. (P1-03) the rev77 byte-door LINT was regex-evadable (`Buffer["from"](x)`, `new Uint8Array(hostile)`, a read in `reference-checker.mjs` the gate never scanned); ROOT fix: harden the lint (bracket/computed forms, scan the whole L1 TCB), HONESTLY re-scope it as a heuristic (a regex cannot be complete — an AST rule is the full version), and add the real guarantee — a BEHAVIORAL totality test that drives every raw-byte entry with a hostile Proxy / forged-`byteLength` subclass / throwing-getter array-like and asserts a structured verdict, never a host throw. (P1-04) `spec-code-sync` scanned only `index.mjs`, so the L1 checker's 54 error codes were unregistered while it claimed `spec == registry == code` over the TCB; ROOT fix: a registered `REFERENCE_CHECKER_ERROR_CODES` set + the gate scans that module too. The through-line (owner's "no patches, only root fix"): a fix that enumerates INSTANCES (this date, this spelling, this regex shape) leaves the mechanism that GENERATES them; the durable fix moves the property into ONE mechanism — a shared obligation set, a prefix table, a probe-inside-try, a behavioral test, a from-source scan of the WHOLE surface.

**Correction (rev79 — round-51: the rev78 "ONE mechanism" fixes were still HAND-ENUMERATED, so each had one more instance; the owner's deeper mandate is that recurrence be STRUCTURALLY IMPOSSIBLE — exhaustive-by-construction + fail-closed, never enumerated from my head).** Round-51 refuted 4 of 5 again, each ONE MORE instance of a class rev78 "closed": lite still accepted a private partition with a NON-HASH `commit` (the differential corpus enumerated envelope/A-label but not commit-type); the SSRF "prefix table" still missed `198.18/15` + the documentation ranges (a hand subset, not the registry); the "total" doors still threw on a REVOKED Proxy — which throws on `Array.isArray`/`instanceof` ITSELF — in `admitArray`/`reducePackage`/`forkChoice` (rev78 fixed three doors, the fixture was ONE Proxy shape); capability-parity certified a surface `full` on `some`-intersection. The unifying root, named by the owner: **INCOMPLETE HAND-ENUMERATION of my own coverage** — a hostile FIXTURE of one shape, a prefix LIST, an obligation CORPUS, a gate predicate `some`. Each is always incomplete, so a diverse model finds the missing element and I add it — forever. The durable fix is NOT the missing element; it is a mechanism that has no "missing element": (P1-02) the totality gate now drives a hostile-fixture BATTERY of every escape shape (throwing-trap Proxy, **REVOKED Proxy**, throwing-index array-like) × the from-source export roster — it found `forkChoice` too, which the hand audit had NOT flagged, and the three primitives moved their `Array.isArray` inside the `try`; (P0-01) the lite↔core differential is now GENERATED over the constructed doc-shape cross-product (id × time × partition-envelope shapes), so a new obligation lite omits fails by construction — plus lite types the private commit as `sha256:hex`; (P1-01) the SSRF classifier is the COMPLETE IANA special-purpose registry (a prefix table of every globally-unreachable IPv4/IPv6 block), not a subset; (P1-03) `full` now means EVERY export of the capability (`every`, not `some`), and a genuine reduced surface declares a machine-readable `subset`. The principle: **enumerate from the source / the authoritative registry / the full product — never from my head; a gate whose fixture I hand-pick will always miss the shape I did not imagine.** **Realization (rev55):** the authority adapters' TRUST config is now
reduced by `admitInert` (side-effect-free) — a config getter/`toJSON` never executes (*"R46 checkAuthorityProof REDUCES the config side-effect-free — a config accessor getter is NEVER executed (the automaton reads DATA, never runs it; this SUPERSEDES the rev45 source-level admission order — no code runs at the boundary at all)"*). The residual `E`s (the signed-proof reads) are
sound by discipline 2 (read-once + content-hash). **Realization (rev56):** `checkAuthorityProof` is now literally
`A ∘ (ρ_package, ρ_config)` — `ρ_config = admitInert → canonJSON` (unsigned, side-effect-free), `ρ_package` (new) reads the
SIGNED proof's `[[Get]]` face ONCE (`admitDeep` the term, collect the referenced witness ids from the inert term, admit each
REFERENCED witness once; an unreferenced witness is not part of the canonical package, so it is never read), and
`A = checkAuthorityProofBytes` over the two reduced byte strings. The whole proof is now read ONCE — a two-face term cannot
show one face to `referencedIds` and another to `canon` (*"R46 (Theorem R — ρ_package) checkAuthorityProof reads the SIGNED package ONCE — a two-face term Proxy (a different term on re-read) yields the SAME verdict as the honest package (referencedIds and canon see the ONE admitted [[Get]] face; no split)"*). Both arguments are reduced INDEPENDENTLY to canonical
bytes, so cross-argument mutation and admission order are structurally impossible; the automaton, not a case-by-case boundary
guard, carries the totality.
**Realization (rev57 — Theorem R's ordering discipline swept to the OBJECT-form sync verify path).** The rev55/56
decomposition closed the cross-argument class on the authority (byte) path; the round-46 self-audit found the SAME class live
on the sync verify surface. `verify`, `resolveAuthority`, and `verifyAnchor` reduce their SIGNED argument by discipline 2
(`admitDeep` reads the `[[Get]]` face), which FIRES a hostile getter — and each admitted its TRUSTED `opts` AFTER, so a
signed-argument getter could mutate the still-live `opts` (drop `requireAuthoritative`, inject `trustRoots`, plant
`substrateVerify`) that the verdict then read. Because a discipline-2 reduction runs code, the reductions are independent only
once BOTH are captured; therefore the OBJECT-form sync verify path admits the trusted opts BEFORE the untrusted signed
argument — the trusted form is captured before any signed-argument getter can run. A behavioral, from-entrypoint gate drives
each entry with an `opts`-mutating signed-argument getter and asserts the verdict is invariant vs the benign call (*"R46 self-audit (Theorem R) verify admits the TRUSTED opts BEFORE the untrusted doc — a doc getter that drops requireAuthoritative cannot rewrite the consumer policy the verdict uses (INVALID stays INVALID; cross-argument order, sync path)"*).
**Realization (rev58 — the totality of the reductions ρᵢ is enforced FROM THE SOURCE, not a hand-roster).** Theorem R requires
each `ρᵢ` to be a TOTAL reduction: a hostile argument yields a structured reject, never a host exception. The round-46
self-audit found the lone door that violated it — `combineSubstrates` SYNC-threw at its plugin-array normalization
(`Array.isArray → .filter`) on a hostile `verifiers` Proxy, because the totality sweep had been a HAND-maintained roster of
exports (round-17/18/19/24/38/39) and this door had simply fallen out of it (the round-44 gate-completeness class, now for
totality). It is fixed (fail CLOSED to an empty plugin list → the combinator claims no substrate → `unavailable`), and the gate
is rebuilt so that the totality of every reduction door is enforced from the SOURCE export list: every
verify*/resolve*/derive*/check*/combine*/fork*/no* export is driven through its entrypoint with a hostile Proxy and asserted
not to sync-throw, with a small PRINCIPLED exclusion (a `*Claim` PRODUCER constructs prover data from TRUSTED args, and
`verifyOrThrow` throws by contract). A new verifier is auto-covered; a new producer auto-excluded (*"R46 self-audit (totality, from-code) — NO public verifier/resolver export SYNC-throws a host exception on a hostile Proxy in every arg position (the SOURCE list is the roster; closes the combineSubstrates gate-completeness gap)"*).
**Realization (rev59 — the totality roster is made EXHAUSTIVE: every export, sync AND async, accounted for).** The rev58
roster covered only the verify*/resolve*/… prefix family and only SYNC throws, so the assurance/evidence ALGEBRA ops
(`assuranceState`/`capAssurance`/`compareEvidenceOrder`/`quorumTrustDomains`/`projectTier`/`deriveAssurance`) and the four
ASYNC entries (`verifyAsync`/`forkChoice`/`witnessNoFork`/`resolveByDiscovery`) sat outside it — total in fact, but held only by
hand-checks. rev59 enumerates EVERY exported function and asserts each is TOTAL on a hostile Proxy — no sync host-throw AND no
async promise-REJECTION — UNLESS it is explicitly classified MAY-THROW (a trusted-input PRODUCER `build*`/`seal*`/`*Claim`, a
byte/string PRIMITIVE, the connector-side `verifiedEvidence`, or the throw-by-contract `assertValid`/`verifyOrThrow`). The one
residual boundary that host-threw — `provePredicates` on a hostile Proxy (a getter fired on destructuring; the round-25 null
tolerance did not reach a Proxy) — is now reduced by `admitDeep` and floors instead of throwing (its output is unbranded, sealed
only by `verify`, so a hostile input floors to LIGHT, never a host throw).
**Correction (rev66 — round-47 P1-03 refuted "from-code EXHAUSTIVE": the SOURCE regex missed 36 of 100 exports).** The rev58/rev59
gates enumerated `matchAll(/export function/)` — which sees only `export function` DECLARATIONS, NOT export-const ARROW functions
or RE-EXPORTS (`export { X } from './reference-checker.mjs'`). The miss was 36 of the 100 function-typed exports, INCLUDING the
byte kernel `checkAuthorityProofBytes` itself, `checkAuthorityProof`, `verifyAuthorityBundle`, `admitDeep`, `contentHash` — so
"totality enforced from the SOURCE export list" (rev58) and "roster made EXHAUSTIVE" (rev59) were overstated. The exhaustive
roster is now the RUNTIME MODULE NAMESPACE — every value whose runtime type is `function` — so an arrow-const / re-export /
future callable cannot evade it; each is TOTAL on a hostile Proxy unless explicitly classified MAY-THROW, and the classification
covers EXACTLY the current throwers (no verdict boundary exempted, no thrower unclassified). No live totality hole hid among the
36 (they are all producers/primitives/classes/helpers) — the miss was a GATE-completeness gap, now closed at its root
(*"R47 P1-03 (roster completeness — RUNTIME namespace) — EVERY function-typed export of the module (100, incl. re-exports + arrow-consts + the byte kernel checkAuthorityProofBytes) is TOTAL on a hostile Proxy UNLESS explicitly classified MAY-THROW (producer / byte-string primitive / verdict class / throw-by-contract); a source-regex miss (arrow-const, re-export, future callable) can no longer evade the gate"*).

**Verification (rev63 — BOUNDED-EXHAUSTIVE model check of the automaton `A`, beyond sampled fuzz).** The Checker Soundness
theorem is proved BY STRUCTURAL INDUCTION on the proof term `π`. Because totality and determinism are COMPOSITIONAL over a
structural recursion, it suffices to verify the INDUCTION STEP for every rule of the closed enum plus the leaf base case, and
induction then extends them to ALL depths. `bmc.mjs` does exactly this, EXHAUSTIVELY up to a bound (not the random sampling of
`reference-checker.fuzz.mjs`): Phase 1 drives every rule × every arity in {want−1, want, want+1} × every witness count in
{0 … max+1} (an unbounded-witness contract capped) × representative children, and asserts each rule's interpreter is TOTAL (no
host throw), DETERMINISTIC (same bytes → same verdict), and CONTRACT-GATED (an off-contract arity/witness count is rejected at
DECODE as `E-TERM-*`, never interpreted to VALID). Phase 2 takes each VALID byte-vector baseline and mutates EVERY string-leaf
position (the whole 1-edit neighbourhood, not a sample), asserting no single edit is accepted — bounded-exhaustive soundness.
The byte kernel `checkAuthorityProofBytes` (the realization of `A`) passes both. (A machine-checked mechanization in a proof
assistant is the tier beyond this; the bounded-exhaustive check is the executable, regression-gated approximation.)
**Correction (rev67 — round-47 P1-01: Phase 1's "representative children" did NOT span the child-judgment algebra).** The GPT
audit refuted "`bmc.mjs` does exactly this": Phase 1 filled child positions with syntactic TEMPLATES that mostly FAIL before
producing a judgment, so a parent rule's handling of a specific child JUDGMENT KIND was never exercised — a fault-injected
`ReinforceMap` that returns child 0's Freshness WITHOUT checking child 1 PASSED Phase 1+2 yet false-accepted a Corroborated
wrapped with a non-MapUnique child 1 (a reachable false accept at depth > 1). The induction step actually needs: for EVERY
child-judgment tuple, the parent is SOUND. **Phase 3 (added rev67)** extracts a witness sub-term for each judgment KIND from the
VALID baselines (rule → concluded kind), then drives every composite rule with a WRONG-kind child at each position (correct
kinds elsewhere, so the rejection ISOLATES the perturbed position) and asserts the parent does NOT yield a VALID conclusion —
verified to CATCH the fault-injected mutant (`ReinforceMap[Freshness, QuorumAgreement]` is flagged). The all-depths claim now
rests on an induction step verified over the child-judgment ALGEBRA, not just child syntax; a fuller property-based interpreter
with injectable child results (and, beyond, a proof-assistant mechanization) remains the next tier.

**Correction (rev72 — round-47 step 3/3: the rev67 note above OVERCLAIMED "the all-depths claim now rests on ... the child-judgment ALGEBRA").** Two honest bounds the rev67 phrasing hid. (i) The baseline witness library held NO `MapUnique` sub-term — the VALID vector set never exercised `ReinforceMap`/`MapUnique` acceptance — so the `ReinforceMap[0]` position was SILENTLY skipped and "every composite rule" was false. Fixed structurally by adding the `accept.reinforce-map` positive baseline (a genuine map-uniqueness proof, populating the `MapUnique` witness → 13/13 composite child-positions now exercised) AND by making the harness SELF-REPORT its coverage: a position skipped for a missing witness kind now FAILS the coverage gate, so the child-algebra claim can never again narrow in silence. (ii) Phase 3 perturbs the child KIND only; a right-KIND child from the WRONG coordinates `(s,n,h)` and any judgment kind still absent from the baselines are the DECLARED residual for the injectable-child-verdict tier — "all depths" names the induction step's KIND dimension, bound to exactly the mechanism the harness runs, no more. This is the third step of the "a claim must not outrun its mechanism" rework, alongside the `resolveKeys` bytes-in surface (rev70) and the from-spec temporal differential (rev71).

**Correction (rev73 — round-47 residual: the rev72 note deferred the child-COORDINATE dimension to an "injectable-child-verdict tier"; that tier is architecturally VOID, and the dimension is now covered).** Two corrections to the rev72 residual framing. (i) **Injectable child verdicts are unsound, not merely "next tier".** A parent rule reads a child's judgment ONLY by re-verifying the child's sub-proof — there is no input path that asserts "child concluded `K` at `(s,n,h)`" without a proof (a fabricated child conclusion is INVALID, verified directly). That is exactly the unforgeable-judgment property the checker exists to enforce; a harness that injected arbitrary verdicts would test a machine the checker is NOT. So child-algebra coverage must be BY CONSTRUCTION — build a real child that concludes the target judgment. (ii) **The coordinate dimension is now covered by construction.** The three cross-child coordinate-unification gates — `ReinforceMap` (`F.(s,n,h) = M.(s,n,h)`), `ReinforceQuorum` (`F.(s,n,h) = Q.(s,n,h)`), and `Corroborated` (all freshness premises share the chain scope) — had NO negative vector; nothing proved they FIRE. The `unify.reinforce-map-cross-coordinate` / `unify.reinforce-quorum-cross-coordinate` / `unify.corroborated-cross-scope` vectors build a fully independent SECOND coordinate-space (a distinct genesis+domain → distinct `(s,n,h)`), prove a genuine `MapUnique`/`QuorumAgreement`/`Evidence` there, staple it onto the coordinate-A freshness, and assert the gate rejects with its exact reason (each is now a security-manifest condition, criterion 8). The rev72 "declared residual" for the coordinate dimension is thereby closed; what remains is a future sweep of the conformance check *messages* for the same claim-vs-mechanism drift, and the owner-deferred proof-assistant mechanization.

**Verification (rev64 — TEMPORAL model check of the key-log state machine, the time dimension the automaton BMC does not
reach).** `bmc.mjs` covers the STRUCTURAL dimension (the proof term); the key-log (§12.2 #75 ROOT 2) is a TEMPORAL state
machine whose keys move active → rotated-out / revoked(retired) / revoked(compromised), with the safety property that a key
NOT ACTIVE at step k cannot authorize a key-log entry at step k. Interleaving bugs (add→retire→re-add, rotate-then-sign-with-
the-old-key, re-revoke a compromised key) hide in specific ORDERINGS a hand-written vector rarely hits. `temporal-bmc.mjs`
enumerates EVERY reachable event sequence up to a bound (LEN 3, four keys → 1020 sequences) and for each: (A) a DIFFERENTIAL
against an INDEPENDENT abstract reference model of the state machine — `resolveKeys` must agree on the resolved (active, all,
compromised) sets, any divergence a counterexample; and (B) an ATTACK — appending an entry signed by EVERY currently
non-active key (retired / rotated-out / compromised) must be rejected `E-KEY` (1008 attacks, all rejected). This is
bounded-exhaustive temporal soundness + implementation-vs-model conformance over the whole interleaving space, complementing
the structural automaton BMC.

**Definition (VerifiedAuthorityContext).** For a genesis document `g` whose class and self-signature VERIFY
(`resolveCheckpointRoots` — P0-2: verify-before-extract):

```
active_genesis := contentHash(g)                       — the hash of the WHOLE signed genesis; never a carried field
scope_id       := H_"ust:authority-scope"(active_genesis)   = H_"ust:authority-scope"(contentHash(g))   (K2)
genesis_epoch  := H_"ust:genesis-epoch"(active_genesis) — DIAGNOSTIC / legacy wire only; no longer part of the scope
ctx            := { scope_id, domain, active_genesis, genesis_epoch, checkpoint_authority, checkpoint-recovery* }
```
The scope is a function of `contentHash(g)`, so it binds the ENTIRE genesis (domain, keys, checkpoint-recovery, capacity,
cadence). The earlier `canon({domain, active_genesis, genesis_epoch})` preimage was redundant (all three are
functions of `contentHash(g)`) and weaker (bound only three fields). Nothing downstream can choose a namespace by
picking `domain`/`genesis_epoch` — they are not in the preimage and, in the kernel, not transmitted.

**Theorem M2 (namespace non-malleability).** Every scope parameter of every downstream predicate is a function of
`(verified genesis, consumer config)` — a publisher cannot choose the namespace any verifier keys by: (i) a
authority checkpoint carrying a non-canonical `genesis_epoch` is `E-MALFORMED` (two rival C₀ over one genesis collide in ONE
uniqueness slot — epoch-split closed); (ii) an evidence receipt with a non-canonical epoch is `E-EVIDENCE` (F.5g);
(iii) an epoch transition binds `to_active_genesis` with a canonical `to_genesis_epoch` (F.5m); (iv) chain
verification roots in the CONTEXT (`authority_root: "verified-context"`) — authority, checkpoint-recovery keys and the C₀
`active_genesis` binding all flow from the one derivation.

**Realization.** `verifiedGenesisContext(genesis)` (the sole context producer), `genesisEpoch`, `authorityScopeId`
(the ONE canonical scope id, shared by context and evidence), and the `context` root of
`verifyAuthorityCheckpointChain` / `deriveCheckpointFreshness`. **K3 (rc.37):** the context is a BRANDED, frozen `GenesisHandle` minted only by `verifiedGenesisContext`; the chain verifier requires the brand, so a caller-shaped look-alike is rejected (round-3 P0-1 closed at the type level). The four opaque handles (genesis / chain / evidence / predicate-graph) generalize the F.5a WeakSet witness to EVERY verified object; `isVerifiedHandle(kind,x)` is the only reader, never a constructor.

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- the seam derives, never copies: *"M2/K2 verifiedGenesisContext derives scope_id = H("ust:authority-scope", contentHash(g)) — binds the whole genesis"*, *"M2 verifiedGenesisContext rejects an unsigned genesis → null (P0-2 carried)"*.
- downstream takes the context: *"C1 chain rooted in a VerifiedAuthorityContext → VALID (authority_root verified-context)"*, *"C1 context-rooted C₀ bound to the context scope: foreign active_genesis → INVALID(E-GENESIS)"*.
- uniform hygiene at every scope-bound object: *"M3 receipt: non-canonical genesis_epoch → INVALID(E-EVIDENCE) (M2 hygiene is uniform)"*, *"M4.4 transition with a NON-canonical to_genesis_epoch → not ok (M2 hygiene uniform)"*.

## F.5g The evidence seam — provenance is a theorem; capability exists only in image(VerifyEvidence_C) (#76 Phase A → M3, rc.36)

F.5a.1 pinned admission for ONE evidence kind (no-fork). Phase A stated the same discipline for ANY connector; the
rc.35 round-2 audit showed the original realization ASSUMED provenance instead of proving it — `verifiedEvidence()`
was an exported constructor any caller could invoke, so a well-formed but caller-MINTED facts object reached the
`corroborated` conjunction (the verifiedEvidence-forge). M3 (UST-6vj C2) rewrites the connector map as a
verification map whose IMAGE is the only carrier of capability.

**Raw evidence is a disjoint union.** `RawEvidence := DirectCryptographicProof ⊔ SignedConnectorReceipt`. The direct
arm is realized by the proofs the core verifies inline (key-log terminality F.5n, verifiable-map uniqueness F.5k,
uniqueness attestations F.5j — each checked against consumer-admitted roots). The connector arm is a SIGNED receipt:
a claim `{version, purpose:"ust:evidence-receipt", domain_shard, active_genesis, genesis_epoch, subject, proof_kind,
facts, payload_digest?, issued_at}` under an Ed25519 signature over the purpose-wrapped preimage
`canon({purpose:"ust:evidence-receipt-signature", claim})` — the F.5h π-discipline. The receipt carries FACTS only:
`facts` bearing `assurance`/`strength`/`trust_domain`/`independent`/`capability`/`attested`/`threshold` are rejected
(`E-EVIDENCE`) at construction AND at verification — the F.5a.1 "never self-declared" rule at the evidence boundary.
`issued_at` is a SIGNED assertion, never proven real time (F.2); a temporal capability arises only from the
proof-kind, never from the stamp.

**The verification map — `VerifyEvidence_C : RawEvidence × Subject × Scope × Config → VerifiedEvidence ⊔ INVALID ⊔
INDETERMINATE`** — runs seven checks IN ORDER: (1) bounds/shape, total, before any crypto; (2) the signature over
the purpose-wrapped preimage, `keyId(pub) = key_id = issuer_id`, and the claim's `genesis_epoch` CANONICAL
(`H_"ust:genesis-epoch"(active_genesis)` — M2 hygiene uniform across every scope-bound object); (3) subject binding —
the claim's `subject` equals the CONSUMER-chosen subject; (4) scope binding — the claim's
`(domain_shard, active_genesis, genesis_epoch)` equals the authority scope of the VERIFIED chain; (5) admission —
the signer is a consumer-admitted connector (`Config.connectors[key_id]`, pinned pub); (6) role — `proof_kind ∈
allowed_proof_kinds` (B4: a connector admitted for `content-addressed` never contributes order/time); (7) totality —
malformation/tamper ⇒ structured `INVALID(E-EVIDENCE)`, never a throw; a genuine receipt not admitted FOR THIS
consumer/scope/subject ⇒ `INDETERMINATE(evidence_unverified)` — absence of admission is not proof of fraud, and it
earns nothing. Only the image is `VerifiedEvidence` `{evidence_id, authority_scope_id, subject_id, proof_kind,
verified_facts, issuer_id, trust_domain, basis}`; the runtime witnesses each member in a process-private set (the
F.5a servedNoFork discipline), and `trust_domain` flows from CONSUMER config, never the receipt.

**Theorem M3 (no capability without verified provenance).** Every evidence value the strong freshness derivation
consumes lies in `image(VerifyEvidence_C)`: its capabilities are those of a proof-kind that a consumer-admitted
connector actually SIGNED, over the correct scope and subject. A caller-constructed look-alike is not in the image,
carries no capability, and lifts no rung — the forge is closed. **B3 attenuation:** no composition step manufactures
a capability — `Caps(out) ⊆ ⋃ Caps(in)` unless a new `VerifiedEvidence` is admitted.
**Realization (rev24 — the ONE input boundary).** A GENUINE branded handle must also carry the EXACT signature-verified
facts, not just exclude look-alikes: `verifyEvidenceReceipt` takes ONE inert deep snapshot of the receipt at entry
(`admitDeep`, reads every value once), and canon/verify/id/handle all read THAT snapshot — so a live getter cannot
return the signed value during verification and an unsigned value during handle construction (the getter-TOCTOU that
minted a genuine handle with unsigned facts — round-26 P0-03; the same snapshot binds `verifiedGenesisContext`)
(*"M3/D getter-TOCTOU on receipt facts cannot mint an EvidenceHandle whose facts ≠ the signed facts → INVALID (round-26 P0-03, L3 closed)"*, *"M2/D verifiedGenesisContext: a getter on the genesis (TOCTOU) cannot mint a context whose scope ≠ the verified genesis → null (round-26 D — snapshot once)"*). **The class stays a CORE map**
`cls : proof_kind → (a σ-sub-algebra of world-coordinates)`: `pow-header-chain ↦` external-commitment/order/time,
`transparency-log ↦` append-only inclusion+consistency (NOT non-membership — exactly F.3.1/F.5a: inclusion+
consistency generate the append-only event, not the `¬∃ rival` event), `authenticated-map ↦` keyed
membership+non-membership, `content-addressed ↦` content-equality/availability, otherwise `opaque` ⇒
`INDETERMINATE(unsupported)`.

**Order is a proof relation, `After(a,b) = {ω : t(a) > t(b)}`.** This event is `ℐ`-measurable only when the
evidence pins both events into ONE order: (i) the same substrate's total order — `a.position > b.position` at a
shared `substrate` ⇒ `proven-after`, `≤` ⇒ `not-after`; or (ii) disjoint intervals — `a.not_before ≥ b.not_after`
⇒ `proven-after`, `b.not_before ≥ a.not_after` ⇒ `not-after`. Two upper bounds (`not_after`) alone, or positions on
DIFFERENT substrates, generate no order event in `ℐ` ⇒ `unproven` (⇒ `INDETERMINATE(order_unproven)` upstream).
This is the F.3 filtration read as a 3-valued relation: comparing two signed RFC3339 fields is NOT a measurement of
`After` (F.2 — a timestamp is a claim), so `compareEvidenceOrder` never does it.

**Quorum is the cardinality of the admitted domain-image.** Independence is the partition `dom_C` of F.5a.1 lifted
to all sources: from a consumer map `dom_C : source_id ⇀ trustDomain`, quorum over an evidence multiset `E` is
`q(E) = |{ dom_C(source_id(e)) : e ∈ E, source_id(e) ∈ dom(dom_C) }| ≥ threshold`. The σ-algebra sees the DOMAIN,
not the endpoint: many connectors/URLs/mirrors under one `dom_C`-value count ONCE; a source absent from `dom_C` is
unadmitted (0); a `trust_domain` carried on the evidence is producer-supplied and never read (F.5a.1 clause 2).
This is the formal content of "strengthened by quorum across INDEPENDENT sources": independence is consumer-defined
domain-distinctness, not connector count and not a self-declared field.

**Realization.** Receipt = `evidenceReceiptClaim` (facts-only ban) + `buildEvidenceReceipt` (purpose-wrapped sign) +
`evidenceReceiptId` (`H_"ust:evidence-receipt"` over `{claim, sig}` only); `VerifyEvidence_C` =
`verifyEvidenceReceipt(receipt, {subject, scope, connectors})` (the seven checks) with the direct arm as the inline
verifiers (F.5j/F.5k/F.5n); the strong-derivation gate = `deriveCheckpointFreshness` admits commitment/anchor only
through the seam (`trust.connectors`) or as an in-process-witnessed token. The RAW facts shape `verifiedEvidence(...)`
remains a builder (throws `E-EVIDENCE` on a self-declared class) but its output carries NO capability; `cls` =
`evidenceClass(proof_kind)`; `After` = `compareEvidenceOrder(a, b) → proven-after | not-after | unproven`;
`q` = `quorumTrustDomains(list, { domains, threshold }) → { count, domains, met }`.

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- the seam (image = capability): *"M3 receipt: admitted connector receipt → VerifiedEvidence (verified_facts, consumer trust_domain, basis admitted-connector-receipt)"*, *"M3 receipt: tampered claim (sig over the pre-tamper preimage) → INVALID(E-EVIDENCE)"*, *"M3 receipt: non-canonical genesis_epoch → INVALID(E-EVIDENCE) (M2 hygiene is uniform)"*.
- admission + role (B4): *"M3 admission: issuer not in consumer connectors → INDETERMINATE(evidence_unverified)"*, *"M3 admission: proof_kind outside allowed_proof_kinds → INDETERMINATE(evidence_unverified) (B4: a content connector never contributes order/time)"*.
- binding: *"M3 binding: receipt subject ≠ required subject → evidence_unverified"*, *"M3 binding: receipt scope ≠ authority scope → evidence_unverified"*.
- the forge is closed: *"M3 forge: a caller-minted evidence object cannot earn corroborated (freshness → evidence_unverified)"*, *"M3 forge: a look-alike VerifiedEvidence (correct fields, no provenance) earns nothing"*; token discipline: *"M3 token: a core-verified VerifiedEvidence token is accepted without re-verification (WeakSet witness)"*, *"M3 token: a verified token bound to a DIFFERENT subject is rejected at admission"*.
- receipt facts-only ban: *"M3 receipt: facts self-declaring assurance/trust_domain/capability → INVALID(E-EVIDENCE) at build AND verify"*.
- facts-only (raw shape, no self-declared class/independence): *"PhA facts-only: connector self-declaring assurance → E-EVIDENCE"*, *"... trust_domain → E-EVIDENCE"*.
- `cls`, transparency-log ≠ non-membership: *"PhA class: transparency-log → append-only (NOT non-membership)"*, *"... authenticated-map → keyed non-membership"*, *"... unknown proof-kind → opaque"*.
- `After` proof relation: *"PhA order: same substrate a.pos>b.pos → proven-after"* / *"... a.pos<b.pos → not-after"* / *"... a.not_before ≥ b.not_after → proven-after"* / *"... b.not_before ≥ a.not_after → not-after"* / *"... overlapping intervals prove neither → unproven"* / *"... cross-substrate positions → unproven"*. The public order coordinate is the SAME closed decode as the kernel (round-32 P0-01): *"R32 order cross-kind: transparency-log wearing pow facts {substrate,position} → unproven (its coord is log_id/index)"* / *"R32 order cross-clock: two intervals on different clocks prove nothing → unproven"*.
- `q` domain-cardinality: *"PhA quorum: two sources in one domain → count 1"* / *"... three domains → count 3, threshold 2 met"* / *"... source not in consumer config → not counted"* / *"... self-declared trust_domain on evidence ignored"*.

All green at REV 44 (conformance 243/0).

## F.5h The authority-checkpoint chain is a well-founded ADAPTED authority process (non-circular latest-head, #76/#77)

The `latest-head` fact (P0-05: which key-log head is current for a name at sequence `n`) is F.5a/F.5d authenticated
non-membership. Establishing it needs an authority checkpoint whose own AUTHORITY does not depend on the head it asserts —
else the naive "the head `Hₙ` signs the authority checkpoint that says `Hₙ` is current" is circular. F.5h formalizes the chain
that carries checkpoint-signing authority non-circularly.

**Three layers — the "sign your own signature" fixpoint is unexpressible.** A authority checkpoint is a body `b`, a preimage
`π(b) = canon({purpose:"ust:authority-checkpoint-signature", b})`, a transcript `(b, sig)`, and an identifier
`id = H("ust:authority-checkpoint", canon({b, sig}))`. Since `sig` signs `π(b)` and `π` EXCLUDES `sig`, no transcript
can commit its own signature (F.2: a document cannot fix its own hash). And `id` is a function of `(b, sig)` ALONE,
so external evidence (anchor receipts, map proofs) is outside `id`: one authority checkpoint under two different anchors has
ONE `id` — immutable protocol state, distinct from evidence ABOUT it.

**Authority is `𝓗_{n-1}`-adapted — the authority checkpoint chain carries its OWN filtration (M4.1).** The index `n` is a
authority checkpoint SEQUENCE, not real time, so the authority checkpoint process is adapted to its own filtration, NOT to the real-time
anchor filtration `𝓕ₜ` (the rc.35 round-2 correction: the two orderings were conflated): `𝓗₋₁ :=
σ(VerifiedAuthorityContext)` (genesis-verified scope + rooted authority, M2), `𝓗ₙ := σ(𝓗₋₁, C₀,…,Cₙ, admitted
checkpoint-recovery/transition evidence up to n)`. Define `Auth(0) =` the context's checkpoint authority (or a pinned prior's
committed next); `Auth(n) =` the key `Cₙ₋₁` committed for `n` (its `next_*` with `effective_sequence = n`), else
`Auth(n-1)`. The signer of `Cₙ` is REQUIRED to equal `Auth(n)`, and `Auth(n)` is a function of strictly-earlier
VERIFIED state only — `𝓗_{n-1}`-measurable. `Cₙ`'s own body cannot set `Auth(n)`: its declared next is
`effective_sequence = n+1`, authorizing only `Cₙ₊₁`. So the authority relation is WELL-FOUNDED — `Auth(n) ≺ Cₙ`
in causal order, no cycle — which is precisely the F.4-style adaptedness the naive self-authorizing head violated.
Real time enters ONLY where an authority checkpoint meets `𝓕ₜ` through evidence (F.5i's `ProvenAfter`), never through `n`.

**Resolve-before-trust; the carried field is redundant.** Verification computes `Auth(n)` from prior state, THEN
checks `sig` against it; the body's `current_key_id` is a diagnostic that MUST equal `Auth(n)` and NEVER resolves
it. A forged `current_key_id` therefore cannot move authority (checked, not used) — the F.5a.1 "never self-declared"
rule on the authority coordinate. Rotation is a deterministic total function (all-or-none; `keyId(next_pub) =
next_key_id`; effective at `n+1`), so `Auth` is a deterministic function of the chain: two verifiers agree (F.5c).
Absent a root for `Auth(0)` (no genesis authority, no pinned prior) the process is unresolved ⇒
`INDETERMINATE(authority_unresolved)`, NEVER a fallback to `Cₙ`'s carried key.

*(F.5h is the AUTHORIZATION backbone; the `corroborated`-freshness derivation on top — terminality + consistency +
external commitment + `proven-after` the target, F.5d × F.5g — is Phase B proper, the next increment.)*

**Realization.** `buildAuthorityCheckpoint` (body), `sealAuthorityCheckpoint` (`π`-preimage sign),
`authorityCheckpointId` (`id` over `{body, sig}` only), `verifyAuthorityCheckpointChain(chain, {genesisAuthority |
pinnedPrior})` (the adapted resolver + resolve-before-trust + rotation totality).

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- adaptedness / well-founded authority: *"AC valid genesis-rooted chain C0→C1→C2 (in-band rotation) → VALID"*, *"AC Cₙ signed by a key not authorized by Cₙ₋₁ → INVALID(E-AUTHORITY)"*, *"AC authority checkpoint signed by its own declared next key → INVALID (no retroactive self-auth)"*.
- resolve-before-trust (carried field redundant): *"AC carried current_key_id ≠ prior-authorized signer → INVALID(E-AUTHORITY)"*.
- three-layer id / external evidence excluded: *"AC checkpoint_id excludes attached external evidence (stable id)"*, *"AC tampered body (sig over the pre-tamper preimage) → INVALID(E-AUTHORITY)"*.
- linkage + sequence + rotation totality: *"AC previous_checkpoint ≠ prior id → INVALID(E-PREV)"*, *"AC sequence skip (0→2) → INVALID(E-SEQ)"*, *"AC keyId(next_pub) ≠ next_key_id → INVALID(E-KEY)"*, *"AC effective_sequence ≠ seq+1 → INVALID(E-SEQ)"*, *"AC partial rotation (next_key_id without next_pub) → INVALID(E-MALFORMED)"*.
- cold start: *"AC cold verifier, no genesis/pinned authority → INDETERMINATE(authority_unresolved)"*; single-epoch: *"AC domain_shard changes within the chain → INVALID(E-MALFORMED)"*.

All green at REV 44 (conformance 257/0).

## F.5i Publisher-checkpoint `corroborated` freshness is a CONJUNCTION — and `corroborated` is the ceiling (P0-05 closed, #76 Phase B)

F.5h authorized the authority checkpoint chain; F.5i derives the freshness verdict a target document `R` earns from it, and
proves the ceiling that closes P0-05.

**The conjunction.** For a target `R` and an authorized chain `C` (head `Cₙ`), define the events
`Authorized(C)` (F.5h: `verifyAuthorityCheckpointChain = VALID`), `ChainConsistent(C)` (M4.2, below),
`Terminal(C)` (SNAPSHOT terminality — `keylog.head` is the entry at position `length-1` AND no successor exists
WITHIN the committed root, F.5n), `Committed(C)` (the authority checkpoint `id` carried by a VERIFIED external-commitment
evidence `e_c` from the F.5g seam with `subject(e_c) = id`), `ProvenAfter(e_c, R)`
(`compareEvidenceOrder(e_c, anchor(R)) = proven-after`, F.5g), and `Binds(C, R)` (`active_genesis(C) =
active_genesis(R)` ∧ same domain). Then

`CorroboratedFresh(R, C) = Authorized ∧ Binds ∧ ChainConsistent ∧ Terminal ∧ Committed ∧ ProvenAfter`.

**`ChainConsistent` — the key log is append-only ACROSS checkpoints (M4.2, closes keylog-rewind).** Per-checkpoint
terminality relates a snapshot to ITSELF; nothing yet related successive snapshots — `C₀` could commit length 10
and `C₁` (correctly linking `C₀`) commit length 4: a SIGNED rewind, both individually terminal. For successive
same-epoch accepted `C_{n-1}, C_n`: `length(C_n) ≥ length(C_{n-1})`; equal length ⇒ identical `root` AND `head`;
and the vector committed by `keylog(C_{n-1})` is a PREFIX of the one committed by `keylog(C_n)`. The full prefix
relation is witnessed by the key-log ENTRY VECTOR itself (≤ 256 by the §13 resolution ceiling — the consumer already
holds it for `resolveKeys`): every authority checkpoint's commitment must recompute over a prefix of that ONE vector, and all
prefixes of one vector are mutually consistent. Monotone length + equal-length-identity hold UNCONDITIONALLY (no
witness needed); a GROWTH edge REQUIRES the prefix witness — without it (K5, round-3 P0-3) append-only across the
growth is unproven and the chain is `INDETERMINATE(chain_consistency_unproven)`, never VALID (length alone does not
prove `[A]→[X,Y]` is an append). A rewind/same-length-rewrite is `INVALID(E-COMMIT)` — a proven contradiction.

Each conjunct is separately measurable, so a MISSING coordinate names itself rather than forging the verdict:
`¬Authorized ⇒ INVALID` (F.5h), `¬Binds ⇒ E-GENESIS`, `¬ChainConsistent ⇒ INVALID(E-COMMIT)` (a signed rewind is
fraud, not indeterminacy), `¬Terminal ⇒ INDETERMINATE(terminality_unproven)`, `¬Committed ⇒
INDETERMINATE(unavailable | evidence_unverified)`, `¬ProvenAfter ⇒ INDETERMINATE(order_unproven)`. Because
`ProvenAfter` is the F.5g proof relation, two `not_after` upper bounds give `unproven ⇒ order_unproven` — never a
silent `corroborated` from comparing two RFC3339 fields (F.2).

**The `corroborated` ceiling (P0-05 closed by construction).** `AttestedFresh = CorroboratedFresh ∧
IndependentAntiEquivocation`, where the anti-equivocation event is `¬∃` a rival checkpoint at the same
`(domain, genesis_epoch, sequence)` — itself authenticated non-membership (F.5a), which a SINGLE publisher does not
control: it can anchor two branches at one sequence, so `IndependentAntiEquivocation ∉ σ(publisher-checkpoint)`.
Therefore `CorroboratedFresh` is STRICTLY below `AttestedFresh`, and the publisher-checkpoint derivation returns
`corroborated` with `anti_equivocation = unverified` — it CANNOT emit `attested`. This is the P0-05 overclaim
removed by the type of the function: the false `attested` path does not exist here; `attested` requires the
independent coordinate of Phase C/#42 (`authenticated-map-uniqueness` or `accepted-witness-quorum`, F.5g quorum).
(`Terminal` is now STRICT last-index terminality — F.5n — not the earlier `head ∈ root` membership.)

**Realization.** `deriveCheckpointFreshness(chain, {genesisAuthority | pinnedPrior, target, commitment,
terminalityProof, trust})` composing `verifyAuthorityCheckpointChain` (F.5h — which enforces monotone/identical
keylog across checkpoints and accepts the optional `keylogEntries` prefix witness, M4.2) × `verifyEvidenceReceipt`
(the F.5g seam) × `compareEvidenceOrder` (F.5g); it returns `{keylog_freshness:"corroborated",
anti_equivocation:"unverified"}` and has no `attested` branch.

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- the conjunction holds ⇒ corroborated: *"PhB all conjuncts (authorized × head∈root × proven-after) → corroborated"*.
- the ceiling: *"PhB CEILING: corroborated carries anti_equivocation:unverified and is NEVER attested"*.
- `ChainConsistent` (M4.2): *"M4.2 keylog grows across checkpoints (2→3) with the prefix witness → VALID"*, *"K5 growth WITHOUT the prefix witness → INDETERMINATE(chain_consistency_unproven) (round-3 P0-3)"*, *"M4.2 keylog REWIND (length 2→1) → INVALID(E-COMMIT) — a signed rewind is caught without any proof"*, *"M4.2 equal-length keylog with a DIFFERENT root/head → INVALID(E-COMMIT) — same-length history rewrite"*, *"M4.2 prefix-extension witness: every authority checkpoint is a prefix of the supplied entry vector → VALID"*, *"M4.2 prefix-extension witness: an authority checkpoint whose keylog is NOT a prefix of the vector → INVALID(E-COMMIT)"*, *"M4.2 witness longer than the authority checkpoint keylog is fine; authority checkpoint longer than the witness → INVALID(E-COMMIT)"*, *"M4.2 keylogEntries over the §13 ceiling (257) → INVALID(E-BOUNDS) before any Merkle work"*.
- named indeterminacy per missing conjunct: *"PhB commitment NOT proven-after target → INDETERMINATE(order_unproven)"*, *"PhB overlapping same-clock intervals prove neither → order_unproven (round-33: rfc3161-tsa facts are CLOSED — clock_id + both real-calendar bounds)"*, *"PhB terminality missing → INDETERMINATE(terminality_unproven)"*, *"PhB commitment not bound to authority checkpoint id → INDETERMINATE(evidence_unverified)"* (M3 — a receipt for a different subject is not admissible evidence here), *"PhB unauthorized chain (wrong signer) → INVALID, freshness unverified"*, *"PhB authority checkpoint active_genesis ≠ target → INVALID(E-GENESIS)"*, *"PhB cold verifier (no root) → INDETERMINATE(authority_unresolved)"*.

All green at REV 44 (conformance 266/0); ChainConsistent added at REV 52.

## F.5j `attested` freshness = `corroborated` ∧ INDEPENDENT uniqueness — the ladder completes (#76 Phase C)

F.5i earned `corroborated` and proved the publisher cannot self-supply the uniqueness coordinate. F.5j brings that
coordinate into `ℐ_C` from an INDEPENDENT source and completes the freshness ladder.

**The conjunction.** `AttestedFresh(R, C) = CorroboratedFresh(R, C) ∧ IndependentUniqueness(C)`. The uniqueness event
`Unique(C) = ¬∃` a rival authority checkpoint at `(domain, genesis_epoch, sequence)` is authenticated non-membership (F.5a),
absent from `σ(publisher)`. It enters `ℐ_C` two ways (both `attested`, distinct basis): (a)
`authenticated-map-uniqueness` — a verifiable map keyed by `(domain, genesis_epoch, sequence)` giving cryptographic
non-membership (the map path, #42); or (b) `accepted-witness-quorum` — the F.5g quorum over a BYTE-IDENTICAL typed
uniqueness claim `u = {purpose:"ust:checkpoint-uniqueness-attestation", domain, genesis_epoch, sequence,
authority checkpoint=head}`, each witness admitted under `C` (issuer ∈ `trustRoots`, valid signature over `canon(u)`), counted
by DISTINCT `dom_C` domains `≥ threshold`.

**Assertion, not observation; independence, not count.** The typed `purpose` is load-bearing: a witness signing `u`
ASSERTS uniqueness (`¬∃ rival`), whereas a co-signed bare observation (`"saw H1"`, a different purpose) is only
membership — corroboration, not non-membership (F.5a). So a wrong-purpose statement is not admitted. And quorum is
`|{dom_C(issuer)}| ≥ threshold` (F.5g): many endpoints under ONE `dom_C` value do not manufacture independence, and
a `trust_domain` inside the signed claim is discarded (F.5a.1). The claims must be byte-identical, so no witness can
weaken the shared statement.

**`attested ⇒ corroborated` (conjunction, not replacement).** The derivation verifies the F.5i corroborated
conjunction FIRST; `¬CorroboratedFresh ⇒ ¬AttestedFresh` regardless of any uniqueness proof — uniqueness on an
unauthorized or unbound authority checkpoint is `INVALID`, never `attested` (the map proves a value occupies the key, not that
the value is a valid authority transition). Uniqueness ALONE never earns `attested`.

**The ladder completes.** `unverified ⊊ fresh ⊊ corroborated ⊊ attested`, each rung adding exactly one measurable
coordinate — `fresh` (a recent authoritative fetch), `corroborated` (F.5i: authorized ∧ committed ∧ proven-after),
`attested` (F.5j: ∧ independent uniqueness). No rung silently upgrades another (F.5a.1); each is earned by bringing
its own coordinate into `ℐ_C`.

**M5 (rc.36) — ONE quorum algebra; uniqueness and checkpoint-recovery are instances.** Every quorum in the model is the same
four-step function: `Admitted_C(E)` (authenticate + bind FIRST, total — a malformed element admits nothing and
throws nothing), `Groups_C` (group by `canon(claim)` AFTER admission — the rc.35 round-2 quorum-poison locked the
group reference to the first BINDING claim before its signature was checked, so a garbage-signed variant suppressed
the honest quorum), `q_C(g)` (count DISTINCT consumer-resolved voters — trust domains here, checkpoint-recovery signers in
F.5l), and adjudication: `0` winners → quorum-not-met, `1` → accepted, `>1` → CONFLICT/equivocation — independent of
iteration order, never first-wins. `ValidThreshold_C(t) := t ∈ ℕ ∧ 1 ≤ t (≤ |voters| when the voter set is closed)`
holds UNIFORMLY — including the aggregate `quorumTrustDomains` (whose `threshold ≤ 0` previously reported `met` from
an empty list, the P0-4 sibling).

**Realization.** `checkpointUniquenessClaim`/`buildUniquenessAttestation` (the typed claim `u`),
`verifyCheckpointUniqueness` = the M5 core (`quorumAdjudicate`: admit → group → count → adjudicate) with voter =
consumer-resolved trust domain, and the `attested` branch of `deriveCheckpointFreshness` (checked only after the
F.5i corroborated conjunction). `verifyCheckpointRecovery` (F.5l) is the SAME core with voter = genesis-authorized
checkpoint-recovery signer and a closed voter set.

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- the conjunction upgrades: *"PhC 2 witnesses, DISTINCT domains → attested (accepted-witness-quorum), anti_equivocation attested"*.
- independence is domain-distinctness: *"PhC 2 witnesses, SAME domain → quorum not met → stays corroborated"*.
- `attested ⇒ corroborated`: *"PhC uniqueness on an UNAUTHORIZED authority checkpoint → INVALID, never attested"*.
- assertion not observation: *"PhC bare observation (wrong purpose) is NOT uniqueness → not admitted"*.
- byte-identical claim / consumer-admitted / binding: *"R34 P0-03 a uniqueness claim with an EXTRA signed field (observed_map_root ∉ the closed VOTE_CLAIM) is DROPPED → quorum not met"*, *"PhC witness NOT in consumer trustRoots → not admitted"*, *"PhC self-declared trust_domain inside the claim → rejected"*, *"PhC uniqueness for a DIFFERENT authority checkpoint → not admitted (binding)"*.
- the M5 algebra: *"M5 quorum-poison closed: an UNAUTHENTICATED first claim-variant cannot suppress the honest quorum (group AFTER admission)"*, *"M5 conflict determinism: two RIVAL claims each reaching quorum → conflict, never first-wins"*, *"M5 conflict is order-independent (reversed array → same conflict)"*, *"M5 ValidThreshold uniform: quorumTrustDomains threshold 0 → met:false (never satisfied)"*, *"M5 total: a malformed checkpoint-recovery leaf (canon-throwing) admits nothing and never throws"*.

All green at REV 44 (conformance 274/0).

## F.5k Authenticated-map uniqueness — position-uniqueness IS non-membership; two predicates, typed key spaces (#42)

F.5j's witness quorum is one basis for the independent-uniqueness coordinate; F.5k is the other — a cryptographic
verifiable map — and it closes the identity axis (`authoritative`) the same way it closes freshness (`attested`).

**Position-uniqueness collapses the universal `¬∃`.** The map is a sparse Merkle tree indexed by `H(key)`: the key's
path is a deterministic function of the key, so a key has EXACTLY ONE leaf. An inclusion proof for `k` returning `v`
therefore proves `k ↦ v` AND `¬∃ v' ≠ v` at `k` — the universal non-membership over rival values collapses to a
single positive lookup (F.5a's prefix-uniqueness, now realized). The map root rides the anchor substrate `Fₜ` (or a
consumer-configured independent map operator), so this coordinate is INDEPENDENT of the publisher — exactly the
`σ(publisher)`-external coordinate F.5i/F.5j required. The tree also decides non-membership of a key directly (an
empty leaf at `H(key)`): `absent(k) ⟺ smtVerify(root, k, ⊥)`.

**Two predicates, one infrastructure, TYPED key spaces (no collision).** The same map serves both, with
domain-separated keys and values so a proof for one predicate is not a proof for the other:
`checkpoint-map` — `key = H("ust:checkpoint-map-key", canon(domain, genesis_epoch, sequence))`, `value =
H("ust:checkpoint-map-value", canon(authority checkpoint))` ⇒ `CheckpointUnique` ⇒ `attested` (freshness axis, F.5j);
`name-map` — `key = H("ust:name-map-key", canon(domain))`, `value = H("ust:name-map-value", canon(active_genesis))`
⇒ `ActiveGenesisUnique` ⇒ `authoritative` (identity axis, F.5a). These are SEPARATE predicates on ORTHOGONAL axes
(F.5a.1): a map may prove one without the other, and a `name-map` proof presented as a `checkpoint-map` proof is
rejected by the key-space type. There is NO generic `verifyMapInclusion(flag)` — the removed-boolean class.

**Basis-agnostic rung tops.** Each axis reaches its top rung by EITHER independent basis: `attested` freshness ⇐
`authenticated-map-uniqueness` (F.5k) ∨ `accepted-witness-quorum` (F.5j); `authoritative` identity ⇐ the name-map
(F.5k) ∨ an accepted external witness (F.5a.1). The RUNG is the measurable coordinate; the BASIS records HOW it
entered `ℐ_C`, and both remain distinguishable in the verdict (F.5a.1) — a witness quorum ATTESTS uniqueness, it does
not become cryptographic map non-membership.

**Realization.** `buildVerifiableMap` (sparse-SMT root + co-path prover), `smtVerify` (inclusion / non-membership),
the typed `checkpointMapLeaf`/`nameMapLeaf`, `verifyCheckpointMapUniqueness` / `verifyActiveGenesisUniqueness`, and
their composition into `deriveCheckpointFreshness` (map branch ⇒ `attested`) and `resolveAuthority`
(`nameMap` branch ⇒ `authoritative`).

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- position-uniqueness ⇒ attested: *"#42 checkpoint-map inclusion → attested (basis authenticated-map-uniqueness)"*.
- a rival at the key ⇒ not unique: *"#42 map shows a RIVAL at the same sequence → not attested → stays corroborated"*.
- conjunction with authorization: *"#42 map uniqueness on an UNAUTHORIZED chain → INVALID, never attested"*.
- name axis authoritative: *"#42 name-map inclusion → identity authoritative (independently_verified, basis map)"*, *"#42 name-map inclusion via verify() composes to VALID:HIGH (authoritative name)"*.
- non-membership (the SMT decides key ABSENCE directly, distinct from a rival value): *"#42 name-map absent (empty map non-membership) → NOT authoritative"*, *"#42 SMT non-membership: absent key → proven non-membership (absent:true)"*, *"#42 SMT rival-value-bound is NOT non-membership (absent falsy)"*.
- typed key-space separation: *"#42 typed key spaces: a name-map proof is rejected as a checkpoint-map proof (no collision)"*.

All green at REV 44 (conformance 282/0).

## F.5l Checkpoint-recovery — a genesis-rooted threshold re-adapts the authority process without breaking well-foundedness (#76 §1.7)

F.5h's authority process halts if the currently-authorized authority checkpoint key is lost: `Auth(n)` was to be committed by
`Cₙ₋₁`, and no one can now produce it. F.5l adds a SECOND, genesis-rooted authority source that re-adapts the
process — without self-authorization and without bypassing any other authority checkpoint predicate.

**A second `𝓕_{n-1}`-measurable authority.** Genesis fixes a checkpoint-recovery key set `RK` (role-separated from data and
authority checkpoint keys, immutable within the epoch) and a threshold `t`. A checkpoint-recovery statement for sequence `n` is authorized
iff `≥ t` DISTINCT keys of `RK` sign the BYTE-IDENTICAL typed claim binding `(domain, genesis_epoch, last_accepted =
id(Cₙ₋₁), effective_sequence = n, replacement_authority)`. The recovered authority `Auth_rec(n)` is then the claim's
`replacement_authority`. Both candidate authorities are measurable in the past: normal `Auth(n)` from `Cₙ₋₁`, and
`Auth_rec(n)` from `RK ⊆ 𝓕_0` (genesis) plus a statement bound to `id(Cₙ₋₁)`. Neither reads `Cₙ`'s own content, so
`Auth_rec(n) ≺ Cₙ` — the F.4/F.5h adaptedness and well-foundedness hold. Checkpoint-recovery is NOT self-authorization: the LOST
key does not sign; the genesis threshold does. The verifier accepts `Cₙ` iff its signature matches `Auth(n)` OR
`Auth_rec(n)`, resolved before the signature is trusted (F.5h resolve-before-trust, extended to a two-element set).

**Threshold authorizes ONE replacement but does NOT prove no rival — the conflict must be DETECTED.** An earlier
claim — that two statements naming different replacements are "each below `t`, so neither recovers" — was FALSE
(P0-05, external audit): with OVERLAPPING quorums a single EQUIVOCATING checkpoint-recovery signer makes two conflicting
replacements EACH reach `t` (e.g. `{R1,R2}` for A and `{R2,R3}` for B under 2-of-3, `R2` equivocating). A threshold
tolerates the LOSS of `|RK|−t` keys; it does NOT guarantee a unique decision under a Byzantine signer. So the
verifier GROUPS distinct valid signers by the canonical claim they signed and REJECTS — a detectable authority
conflict, never an array-order-dependent pick — if MORE THAN ONE distinct replacement reaches `t`; it also requires
`1 ≤ t ≤ |RK|` (`t = 0` is not authorization). Threshold is formal AUTHORIZATION of one replacement; the independent
rule that SELECTS it is UNIQUE threshold-attainment, exactly as F.5j/F.5k separate authorization from anti-equivocation.

**Bounded and non-bypassing.** `effective_sequence = n` binds checkpoint-recovery to EXACTLY the next authority checkpoint; it
re-authorizes the SIGNER coordinate only. `Cₙ` still passes every other predicate — sequence, `previous_checkpoint`
linkage, rotation exactness, terminality, consistency, external commitment, and (for `attested`) independent
uniqueness. So checkpoint-recovery is a re-rooting WITHIN the F.5h chain, not an escape from it; and because `RK` is
genesis-fixed and role-separated, a normal authority checkpoint key can never silently replace the dormant emergency roots.

**Realization.** `checkpointRecoveryClaim`/`buildRecoveryStatement`/`verifyCheckpointRecovery` (the typed multisig)
and the checkpoint-recovery branch of `verifyAuthorityCheckpointChain` (`{recoveries, recoveryKeys, recoveryThreshold}` — the
matched signer, normal or recovered, becomes the authority in force for the next sequence).

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- threshold re-authorization: *"RECOVERY 2-of-3 (lost key K1) authorizes replacement KR → chain VALID"*, *"RECOVERY 1-of-3 (below threshold) → chain INVALID(E-AUTHORITY)"*, *"RECOVERY valid 2-of-3 → replacement_authority + threshold + 2 signers"*.
- distinct signers / agreement on one replacement: *"RECOVERY same signer twice → counts once → quorum not met"*, *"RECOVERY conflicting replacements (non-identical claims) → no quorum (must agree on ONE)"*, *"RECOVERY signer NOT in the genesis checkpoint-recovery set → not counted"*.
- well-formed + bound: *"RECOVERY threshold-complete malformed replacement (BOTH signers agree on key_id ≠ keyId(pub)) → NOT recovered (admitAuthorityKey binds the pair; round-36 P1-01/P2-01 — the vacuous single-malformed vector could not see it)"*, *"RECOVERY effective_sequence ≠ last+1 → not recovered (only the next authority checkpoint)"*, *"RECOVERY stale last_accepted_checkpoint → not recovered (bound to the prior)"*.
- non-bypass: *"RECOVERY does NOT bypass authority checkpoint validation (recovered signer, but malformed rotation → E-MALFORMED)"*.

All green at REV 45 (conformance 293/0).

## F.5m Genesis-epoch transition — a signed re-rooting that extends the adapted process across epochs (#76 audit-8)

F.5h's authority process runs WITHIN one genesis epoch. A new epoch `B` succeeding `A` must re-root the authority
without breaking the causal structure and without a self-declared reset. F.5m is the signed hand-off that does so.

**Adaptedness across the boundary — the destination is a VERIFIED genesis, never a free label (M4.4).** The
transition `τ` is a typed statement SIGNED BY epoch A's authority — the authority in force at A's final authority checkpoint
`F_A` — binding `(domain, from_epoch = A, from_final_checkpoint = id(F_A), to_active_genesis = contentHash(g_B),
to_epoch = H_"ust:genesis-epoch"(to_active_genesis), to_checkpoint_authority, to_initial_sequence)`. The rc.35
round-2 correction: `to_epoch = B` used to be a free string, so a transition could seed an epoch that binds NO
genesis; now `to_active_genesis` is REQUIRED and `to_genesis_epoch` must be CANONICAL to it (the M2 hygiene,
uniform on both sides of the boundary) — with M2 on the authority checkpoint side, the epoch-initial `C₀ᴮ` provably LIVES IN
the genesis the transition bound (`active_genesis(C₀ᴮ) = τ.to_active_genesis` is derivable; the explicit chain check
remains as the hash-collision belt). Epoch B's initial authority checkpoint `C₀ᴮ` binds `previous_epoch_final_checkpoint =
id(F_A)`, has `sequence = to_initial_sequence`, and is signed by `τ.to_checkpoint_authority`. So `Auth(C₀ᴮ) =
τ.to_checkpoint_authority`, and `τ` is signed by `Auth(F_A)`, measurable in epoch A's past (`𝓗`-adapted, F.5h) and
bound to `id(F_A)`. Hence `Auth(C₀ᴮ) ≺ C₀ᴮ`: the adaptedness continues UNBROKEN across the epoch boundary — epoch
A's authority CHOOSES epoch B's, exactly as `Cₙ₋₁` chooses `Cₙ`. It is a re-rooting inside the same well-founded
process, not a new independent root.

**No silent reset.** A authority checkpoint whose `genesis_epoch` differs from the prior WITHOUT a valid `τ` is
`INVALID(E-MALFORMED)`: an epoch cannot re-root the authority or reset the sequence on its own say-so. The sequence
reset (to `to_initial_sequence`) is AUTHENTICATED by `τ`, never free; `C₀ᴮ` must bind `id(F_A)` (`E-PREV`) and match
the transition's initial sequence (`E-SEQ`). The domain never changes across `τ` (a different domain is a different
publisher, not an epoch transition).

**Composition.** Within epoch B the chain runs normally and may itself invoke checkpoint-recovery (F.5l). Because the map key is
`(domain, genesis_epoch, sequence)` (F.5k), the per-epoch sequence namespace keeps authority checkpoint uniqueness
well-defined across epochs — a reset to 0 in epoch B does not collide with epoch A's sequence 0.

**Realization.** `epochTransitionClaim`/`buildEpochTransition`/`verifyEpochTransition` (the typed hand-off) and the
epoch-crossing branch of `verifyAuthorityCheckpointChain` (`{epochTransitions}` keyed by `to_genesis_epoch`; the
transition's `to_checkpoint_authority` becomes the resolved signer for `C₀ᴮ`).

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- adapted re-rooting: *"EPOCH A→B with authenticated transition → chain VALID (initial seq 0)"*, *"EPOCH verifyEpochTransition valid → to_checkpoint_authority + to_initial_sequence"*.
- no silent reset: *"EPOCH silent reset (no transition supplied) → INVALID(E-MALFORMED)"*, *"EPOCH transition NOT signed by epoch A authority → INVALID(E-MALFORMED)"*.
- the destination genesis is bound (M4.4): *"M4.4 transition without to_active_genesis → not ok (no free epoch label)"*, *"M4.4 transition with a NON-canonical to_genesis_epoch → not ok (M2 hygiene uniform)"*, *"M4.4 transition bound to a DIFFERENT destination genesis than the authority checkpoint lives in → INVALID (no cross-genesis seeding)"*.
- binding: *"EPOCH B C₀ does not bind the prior-epoch final authority checkpoint → INVALID(E-PREV)"*, *"EPOCH B C₀ sequence ≠ transition to_initial_sequence → INVALID(E-SEQ)"*, *"EPOCH transition bound to wrong from_final_checkpoint → not ok"*, *"EPOCH transition to_checkpoint_authority malformed (key_id ≠ keyId(pub)) → not ok"*.

All green at REV 45 (conformance 301/0).

## F.5n Strict key-log terminality — head is the LAST entry, not merely a member (#77)

F.5i's `corroborated` needs the checkpoint head to be TERMINAL: the latest key-log entry, with no more-recent
revoking successor. Bare membership `head ∈ root` is NOT terminality — a log that ALSO holds a successor still
contains `head`, so membership is satisfied while the head is stale.

**An earlier construction was UNSOUND (P0-02, external audit).** Committing the key-log as a positioned SMT keyed by
`H(index)` and proving `Inclusion(L-1) ∧ NonMembership(L)` proves only that index `L` is empty — it says NOTHING
about indices `L+1, L+2, …`. Because hashed-index leaves are scattered, `[L, ∞)` is not a subtree, so a
single-coordinate non-membership cannot cover the suffix: a prover commits entries at `{0, 2}`, claims `length = 1`,
proves `pos 1` empty, and hides the entry at `pos 2`. Sparse-dictionary absence at one coordinate is not
prefix-contiguity — the claim "non-membership at `L` proves nothing follows" was false.

**Terminality is a SNAPSHOT property of a SIZE-BOUND vector commitment (M4.3).** The key-log is an ORDERED Merkle
over EXACTLY `L` leaves (padded to a power of two with a domain-separated empty leaf), and the committed root binds
the size: `root = H("ust:keylog-commit", {length = L, merkle_root})`. `SnapshotTerminal(root, L, head)` holds iff
WITHIN the fixed committed root of width `next-pow2(L)`: `head` is the leaf at index `L-1`; every RIGHT sibling on
its authentication path (each time the path node is a left child) is the empty-subtree default for its level; the
proof depth is EXACTLY `ceil(log2(width))` with the index fully consumed (the P0-5 refinement — an under-depth proof
recomputes a smaller tree); and the recomputed root equals the committed root. This proves the admissible index
domain of THIS SNAPSHOT is exactly `[0, L-1]` — no committed leaf exists at or beyond `L` *in this root*. It is
deliberately NOT a claim about "the suffix `[L, ∞)` forever" (the rc.35 round-2 over-strength): nothing about a
FUTURE, larger snapshot follows from one commitment — that relation is `ChainConsistent` (F.5i/M4.2, append-only
ACROSS snapshots), and currency against real time is `ProvenAfter` (F.5i). Freshness is the COMPOSITION of a
snapshot-terminal, chain-consistent, committed, proven-after, authorized checkpoint — three orthogonal predicates,
none overloaded. Still `SnapshotTerminal ⊋ HeadInRoot`, and — unlike the SMT version — sound against a successor at
ANY index of the committed tree, adjacent or not.

**Realization.** `buildKeylogCommitment(entryHashes)` (ordered size-bound Merkle: `root`/`length`/`head`/`merkle_root`
/`headProof = {index, siblings}` + a `prove(index)`) and `verifyKeylogTerminality({root, length, head}, {headProof})`
(index `= L-1` ∧ every right sibling on the path is that level's empty default ∧ recomputed
`H("ust:keylog-commit", {length, merkle_root})` equals `root`), composed into `deriveCheckpointFreshness` as the
`Terminal` conjunct (F.5i).

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- terminality holds for honest logs: *"TERM honest length-1 log (head at pos0, nothing at pos1) → terminal"*, *"TERM honest length-2 log (head at pos1, nothing at pos2) → terminal"*.
- a hidden/truncated successor is caught: *"TERM strict catches a HIDDEN SUCCESSOR (length lies)"* — now via the P0-5 proof-depth check (siblings ≠ ceil(log2(width))) as well as the right-subtree-empty test.
- head must sit at the terminal index: *"TERM wrong head at position L-1 → not terminal"*.

Sound against the P0-02 reproduction (`security-regression.mjs`: a real length-3 log presented as length-1 ⇒ not terminal).

## F.5o Discovery attestation measures REPLICATION; independence is not in `σ(bytes)` (#102)

The serving contract of §20.1 is the one normative surface that renders a verdict and had **no object in this
model**. That is why the independence discipline of F.5a.1 — stated for witnesses, restated for quorum in F.5j —
never reached it, and the discovery attestation has been reporting an independence claim it cannot decide.

**The observable.** For a domain `n` with primary genesis `g`, a locator set `L = {ℓ₁, …, ℓ_k}` is offered as
companion copies. A verifier fetching `ℓ` observes exactly one thing: the byte-string `B(ℓ)`. Define

  `Rep_L(n) = ∀ ℓ ∈ L : contentHash(B(ℓ)) = contentHash(g)`

`Rep_L` is measurable in `σ(bytes)`: fetch, hash, compare. It needs no consumer configuration, which is precisely
why it is attestable by a stranger — and precisely why it cannot carry the independence coordinate.

**Independence, lifted.** F.5a.1 fixes independence as the consumer partition `dom_C`. Lifted from issuers to
locators, `dom_C : locator → trustDomain`, the event of interest is `Ind_L(C) = |{dom_C(ℓ) : ℓ ∈ L}| ≥ 2`.

**Theorem F.5o (replication does not imply independence).** `Rep_L(n) ⊬ Ind_L(C)`.
*Proof.* The verifier's whole observation of `L` is the tuple `(B(ℓ₁), …, B(ℓ_k))`. Fix any two locators serving
byte-identical genesis. That same tuple arises when the locators are two hostnames on one provider, one account,
one region (`|{dom_C(ℓ)}| = 1`) and when they sit in genuinely disjoint failure domains (`= 2`). The two worlds are
observationally identical, so `Ind_L` is not measurable in `σ(bytes)` and no function of the observations decides
it. ∎

**Corollary F.5o (why the declaration site decides whether this is a mislabel or a self-grant).** `Rep_L` reported
as independence is an overstatement whoever chose `L`. But when `L` is CONSUMER-supplied the consumer at least
selected the substrates it wanted compared; when `L` is PRODUCER-declared — a locator list in the operator's own
profile or genesis — a publisher raises its own independence coordinate by choosing which two URLs to name. That is
exactly the self-declaration Theorem F.5a.1 excludes, transposed from the witness axis to the serving axis, and it
is F.5j's clause verbatim: *many endpoints under ONE `dom_C` value do not manufacture independence*.

**The honest decomposition.** §20.1's fourth probe reports `Rep_L` under its own name — byte-agreement across
declared copies, an integrity property and a real one. The independence coordinate enters this axis as it does
every other: through `C`, or through external evidence, never through the publisher's locator list. A publisher
declaring companions is therefore declaring a LOCATOR (where to look, checkable, and a false one only costs the
publisher), never an ASSURANCE.

**Binding: realized** — *"#102 discovery: byte-agreement across declared copies is REPLICATION — two locators under one substrate satisfy it"*, *"#102 ADVERSARIAL: a producer-declared locator set does NOT raise the independence coordinate (F.5a.1 transposed to serving)"*.

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- replication is decided from bytes alone, and is silent about substrate: the two-locators-one-substrate case PASSES the replication predicate and yields no independence.
- the adversarial direction: a locator set named by the producer cannot move the verdict's independence coordinate, matching F.5a.1's clause (2).

## F.5p Absence is TWO facts, and only a declaration separates them — while a declaration may add, never relocate (#102)

F.5o gave the serving axis an object. This section gives it the piece §20 promised and never delivered: the
operator profile is normative prose that **no tool has ever fetched** — the code reaches `ust-genesis`,
`ust-keylog`, `ust-cadence` and `ust-witness`, and never `/.well-known/ust`. So every optional surface is judged
on observation alone, and observation cannot tell two very different worlds apart.

**State update (2026-08-03, #135), and the argument below is unaffected.** A reader now exists: the discovery
check fetches `/.well-known/ust` and takes `D` from its `serves` array. The 2×2 is decided by the core exactly as
stated. What the first reader turned from latent into live is a question this section did not have to ask while
nothing read the document — what a verifier does with a profile key it does not know — and F.5p.1 answers it.

**The collapse.** Let `S` be an optional surface for domain `n` (witness, cadence, a companion copy). A verifier
fetching it observes `obs(S) ∈ {present, absent}`. Two situations produce `absent`:

- `¬offered(S)` — this operator does not run that surface. The property is SETTLED: unattestable, now and later.
- `offered(S) ∧ unreachable(S)` — it exists and did not answer. The property is UNKNOWN and may attest tomorrow.

These are different facts with different consequences, and `σ(obs)` contains neither: both render `absent`. A
verifier that reports one `skip` for both is not being cautious, it is discarding a distinction it was never given.

**The separator, and why it is safe.** Let the profile carry `D ⊆ Surfaces`, the surfaces the operator DECLARES it
serves. The verdict is then a function of the PAIR:

| | `present` | `absent` |
|---|---|---|
| `S ∈ D` | attested from the bytes | **FAIL** — a declared surface that does not answer is a promise not kept |
| `S ∉ D` | attested from the bytes | NOT OFFERED — settled, not a transient |

Two properties make this admissible under the never-self-declared invariant (F.5a.1). First, **declaring is
monotone in obligation only**: adding `S` to `D` can only turn a `skip` into a `FAIL`, never a `skip` into a pass.
Second, **the top row does not consult `D`**: a surface that is THERE is evidence whichever way the profile reads,
so silence cannot hide it. A profile is therefore a locator-and-obligation document — it can cost its author and
can earn its author nothing, which is exactly the shape F.5o admitted for copies.

**Theorem F.5p (a profile may ADD a locator and may never RELOCATE one).** Let `loc_std(S)` be the well-known
location fixed by §12.1/§20.1 and `loc_D(S)` a location named in the profile. If a verifier resolved the trust
chain at `loc_D`, then control of the profile would imply control of where authority is read — and the profile is
served by the same host whose authority is in question, so the resolution would be rooted in the claim it is
meant to check. Hence `loc_std` is the ONLY resolution root for genesis, key-log, witness and cadence, and a
profile locator is admissible strictly as an ADDITIONAL copy under F.5o (compared by `content_hash`, never
substituted for). *Proof.* Resolution at `loc_D` makes the map `n ↦ authority(n)` measurable in σ(bytes served by
`n`), which is the self-rooting F.5a.1 excludes; `loc_std` is fixed by the specification and outside the
publisher's choice at verification time. ∎

**What this corrects in the specification.** §20 lists "key-log location" among the operator's profile choices,
which is exactly the relocation this theorem forbids. Nothing reads it — the profile has never been fetched — so
no deployed verifier resolves that way; the clause is a latent contradiction with §12.1 rather than a live one,
and it is corrected in the same change that first gives the profile a reader.

**Binding: realized** — *"#102 ADVERSARIAL: a profile cannot RELOCATE a standard surface — a named key-log location is refused, resolution stays at the well-known path"*, *"#102 ADVERSARIAL: an UNDECLARED surface that is PRESENT is still attested — silence cannot hide evidence"*.

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- the 2×2 is decided by the core, not by each tool: declared+absent FAILS, undeclared+absent is NOT OFFERED, and both present cases attest.
- declaring is monotone in obligation: no declaration turns an absent surface into a pass.

## F.5p.1 A profile BINDS and DESCRIBES, and one extension rule cannot serve both (#135)

F.5p gave the profile its separator while nothing read the document. With a reader, the document's own shape
becomes a question, and the measurement that forced it is the reference operator's: its profile carries
`summary`, `rights`, `paid`, `time_semantics` and `links` — prose addressed to a person, binding nothing — and
carries no `serves`, no substrate list and no copy locator, while serving a witness log and a key log and
anchoring into two substrates. **CLOSED IN PART, and measured by a read-only fetch on 2026-08-05:** the served
profile now carries `declares` with `serves: ["witness"]` and three `copies` locators for genesis, keylog and
witness. `substrates` is still absent — which under F.5p's monotonicity is the honest floor rather than a
residual defect: declaring can only add an obligation, so an undeclared substrate is not-offered, never a
failure. This note was added later; the paragraph below is the measurement the theorem rests on. The machine-read half was absent for months and no surface noticed, because
nothing in the document says which half a key belongs to.

**Two requirements, each independently forced, on what a verifier does with a key it does not know.**

- **A BINDING key may not be silently dropped.** §20.1 already settles this for one instance: an implementation
  asked to carry an independence coordinate MUST answer `E-REPLICATION` rather than accept and ignore it, because
  a field silently dropped is one some later surface starts reading. The argument does not depend on which field
  it was — dropping any member of the declaration set converts a stated obligation into no obligation, silently,
  on the side that was supposed to be checking.
- **A DESCRIBING key must be silently dropped.** Otherwise one added line of operator prose fails every deployed
  verifier, and the profile becomes unextendable — which destroys the monotone-in-obligation property F.5p rests
  on, since an operator that cannot safely add a field cannot safely add an obligation either.

**Theorem F.5p.1 (no flat profile satisfies both).** Let `P` be the served profile, `K` its key set, and
`bind: K → {0,1}` the predicate that `k` creates an obligation a verifier checks. Let `V` implement specification
version `v`, and let `K_v` be the keys `v` defines. For `k ∉ K_v` the verifier must evaluate `bind(k)` to choose
between refusing and ignoring. But `bind` is fixed by the specification, and `k ∉ K_v` says precisely that `v`
does not define `k`: `bind(k)` is not in `V`'s information. So on exactly the keys where the choice matters, the
two requirements above are jointly unsatisfiable over a flat `P`. *Proof.* Both requirements are conditions on
`V`'s action at `k ∉ K_v`, and they demand opposite actions; a verifier that could tell them apart would be
computing `bind(k)` from `σ(P, v)`, which does not contain it. ∎

**Corollary F.5p.1a (the partition must be POSITIONAL, and a naming convention will not do).** Partition `P` into
`P_open`, where `bind ≡ 0` by construction, and `P_closed`, where `bind ≡ 1` by construction, at positions the
specification fixes. Then `bind(k) = [k ∈ P_closed]` is computable from POSITION, which `V` observes, without
knowing `k` — an unknown key in `P_open` is prose and is ignored, an unknown key in `P_closed` is a declaration
this verifier cannot honour and is refused. A partition by key NAMING — prefix, suffix, any convention — restores
the defect and adds a worse one: the publisher chooses the name, so the publisher chooses whether its own
statement binds it, which is the self-grant F.5a.1 excludes.

**Corollary F.5p.1b (under-declaration remains safe, unchanged).** A publisher may place a fact in `P_open` and
bind nothing by it. It gains nothing: the top row of F.5p's table does not consult `D`, so a surface that is
PRESENT is attested whether declared or not, and moving a fact out of `P_closed` can only remove an obligation,
never create a pass. This is why the partition needs no anti-evasion rule — F.5p's monotonicity already supplies
one.

**Corollary F.5p.1c (the closed half is nested, not a second path).** `P_closed` sits inside the profile document
rather than at a well-known path of its own. A second path is a second surface that must be kept in byte
agreement with the first, and a divergence between two served copies of one operator's declarations is precisely
the failure F.5o measures for companion copies — here manufactured by the specification rather than by an
operator. One document, one fetch, one cache identity, and `loc_std` for the profile stays a single point under
F.5p's relocation theorem.

**Binding: pending — thelabmd/UST-Protocol#135.** The 2×2 of F.5p is realized; the partition is not. Today the
reader takes `serves` from the flat top level, which is `P_closed` of size one with no unknown-key rule at all.

**Conformance (math ⇒ code ⇒ green vector, once realized).**
- an unknown key inside the closed half is REFUSED, and the same key inside the open half is ignored — the two
  differ only in position, so the vector pair is the theorem.
- a declaration placed in the open half binds nothing and grants nothing: the present-surface row is unchanged.

## F.5p.2 The absence of an ALARM is two facts, and only a positive assertion separates them (#137, operator measurement)

F.5p separates two facts hiding behind one `absent` on the surface being OBSERVED. The same collapse occurs one
level out, on the OBSERVER, and there it is easier to miss because the observer is ours.

**The collapse.** Let `W` be a watcher reporting on a publisher's liveness, and let it speak only on a change of
state — which is correct discipline, since a watcher that repeats itself every tick trains its reader to ignore
it. A reader then observes `silence(W)`. Two situations produce it:

- `healthy(P)` — the publisher is printing and there is nothing to say;
- `¬running(W)` — the watcher is dead, mis-configured, or its own reads are failing.

These are opposite conclusions, and `σ(silence)` contains neither. **A liveness conclusion drawn from silence is
therefore unfounded** — it is the same shape as concluding validity from the absence of a refusal, which the
tiers exist to prevent.

**Measured, 2026-08-04. CLOSED 2026-08-04 on the operator; noted here 2026-08-05.** The flag was corrected to
carry the `_ENABLED` suffix `actionEnabled` actually builds, and the watcher now announces its FIRST successful
observation once, with the `ust_id` of the slot it read — so silence is no longer the only signal it emits. The
paragraph below is kept in the present tense of the measurement because it is the evidence for the theorem, not
a report of an outstanding defect. A watcher was enabled on the reference operator, printed its start line, and went
quiet. Quiet was the designed signal for health. A watcher whose fetch had broken would have produced a byte-
identical trace. And one level further in: the flag that enables it is named `<SVC>_<ACTION>_ENABLED`; set
without the suffix it read as absent, so the watcher **did not start, silently** — the same collapse, one turn
of the screw down.

**The separator.** A single POSITIVE assertion that the watcher has read the observed surface at least once —
`observed(W) = true` — announced exactly once and never repeated. Silence after it is again health, and now it is
health that was DEMONSTRATED rather than assumed. The assertion is monotone in the F.5p sense: it can only ever
add an obligation on `W` (having claimed to observe, it must keep observing or say otherwise) and can never
raise the publisher's verdict, because `W` supplies nothing to the publisher's inputs (F.5.1: the observer moves
neither `x̂` nor `(ℐ_v, ρ_v)` of any verifier judging `P`).

**Corollary F.5p.2a (a self-observer separates its own silence, never its own independence).** The positive
assertion tells a reader that `W` is alive. It says nothing about whether `W` is independent of `P`, and when
publisher and watcher are the same party it cannot: independence is not in `σ(bytes)` (F.5o), and a watcher
announcing its own liveness is announcing exactly the property it is entitled to announce and no other.

**Binding: pending — thelabmd/UST-Protocol#158.** #137 and #138 both closed (2026-08-06 and 2026-08-04) and this line went on naming them for a week — the decay #156 names. What is owed is not the behaviour but a check the section can CITE. An earlier draft marked this `none — definitional`, which was
wrong and closed the section's path DOWNWARD. The rule is protocol mathematics CONSUMED BY AN OPERATOR, and it
descends: a report that lists rungs must distinguish a rung CHECKED AND MET from one NOT ATTEMPTED, which is this
section applied to the report rather than to a watcher. Silence about a rung is the same collapse — *nothing was
wrong* and *nothing was asked* produce one blank, and a reader deciding whether to act cannot tell them apart.

**Conformance (math ⇒ spec ⇒ code ⇒ green vector, once realized).**
- a rung the report did not attempt is reported distinguishably from one it attempted and found met;
- a watcher-shaped surface asserts observation POSITIVELY at least once; absence of an alarm never carries health;
- the assertion adds an obligation on the observer and never raises the observed party's verdict (F.5.1).

## F.5q Darkness is a UNIVERSAL claim, so its domain must be declared (#120)

F.5p separated the two facts hiding behind one `absent` on the DISCOVERY axis. The ANCHORING axis has the same
defect and had no declaration: a publisher may anchor a closed window into several substrates, and an observer
looking at one of them and finding nothing cannot say what happened.

**The lifted 2×2.** Let `A ⊆ Subs` be the substrates the profile declares the publisher anchors into, and for a
closed window `w` let `obs(s, w) ∈ {anchored, absent}`. The per-substrate verdict is F.5p's table with the
subject changed — declared+absent FAILS, undeclared+absent is not-offered, and anchored attests either way — so
it is the SAME function, applied to a different subject, and must be realized by the same code rather than a
second copy of the reasoning.

**What is new is the roll-up, and it is where the interesting negative lives.**

  `dark(n, w) := ∀ s ∈ A : obs(s, w) = absent`         — the publisher printed nothing anywhere it promised to
  `partial(n, w) := (∃ s ∈ A : obs(s, w) = absent) ∧ ¬dark(n, w)`   — named legs are down, the chain still prints

**Theorem F.5q-a (darkness is not decidable from one substrate).** Fix any `s ∈ A`. Then `dark(n, w)` is not
measurable in `σ(obs(s, w))`.
*Proof.* `obs(s, w) = absent` occurs in two distinct worlds: one where every substrate in `A` is silent, and one
where only `s` is. The observation is identical in both, so no function of it separates them. ∎

That is the same shape as F.5o — a single observation that two different worlds produce — and it is the formal
statement of a mistake made while filing this: one substrate was checked and the conclusion was written about the
publisher. The honest reading of a single silent leg is `∃`, never `∀`.

**Theorem F.5q-b (the universal quantifier needs its domain).** `dark(n, w)` quantifies over `A`. An observer
without `A` can form EXISTENTIAL statements — **this substrate is silent** — and cannot form the universal one at
all, because a quantifier over an unknown set is not a claim. Hence the declaration is not a convenience that
sharpens an available verdict; it is what brings the verdict into existence.
*Proof.* Measurability of `∀ s ∈ A : P(s)` requires `A` to be determined; with `A` unknown the observer's
σ-algebra contains `P(s)` for each substrate it happens to know and no event equal to their intersection over the
true `A`, since that intersection is not a function of what was observed. ∎

**Corollary (why an outside observer without the declaration is useless in both directions).** Missing `A`, an
observer either raises an outage on every dropped leg — `∃` reported as `∀` — or reports nothing while the
publisher is genuinely dark, because it never had grounds for the universal claim. Both failures are forced, not
sloppy: the information was never present.

**Admissibility, unchanged from F.5p.** Declaring a substrate is monotone in obligation — it can turn a shrug
into a FAILURE and never a shrug into a pass — and the anchored row never consults the declaration, so silence in
the profile cannot hide an anchor that exists. And, as in F.5p, a declared substrate is a place to LOOK: validity
is decided by that substrate's own verification, never conferred by the publisher having named it.

**Binding: realized** — *"#120 ADVERSARIAL: darkness is NOT decidable from one substrate — one silent declared leg yields PARTIAL, never dark"*, *"#120 ADVERSARIAL: an UNDECLARED substrate carrying an anchor still counts — silence in the profile cannot hide evidence"*.

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- the per-substrate verdict is the SAME function as F.5p's, not a second copy.
- the roll-up separates dark from partial, and an empty declared set yields neither.

### F.5q-c The WINDOW family is an index set, not a quantified one — and the chain already settles most of it

F.5q fixes a closed window `w` and quantifies over the substrate set `A`. Its proof is a statement about
`σ(obs(s, w))` for that fixed `w`, so nothing in it determines WHICH windows are in scope. `A` is quantified
inside a verdict; the window family `W` is the INDEX SET of a family of verdicts. Reusing F.5q here would be a
correct argument applied one layer off, and the distinction is what keeps the following result small.

**Theorem F.5q-c (coverage and omission are measurable in the commitment chain alone).** Let the commitments be
`prev`-chained and let each carry its window as `[from, to]` in `ust_id` terms (§11.3, rev84). Then for a
window `w` and a chain `Γ`:

  `covered(w, Γ) = [ ∃ γ ∈ Γ : from(γ) ≤ w ≤ to(γ) ]`     — measurable in `σ(Γ)`
  `gap(γ_n, γ_{n+1}) = [ from(γ_{n+1}) > to(γ_n) ]`        — measurable in `σ(Γ)`

Neither expression contains a declaration. *Proof.* Both are functions of fields carried by the chain's own
documents, and `Γ` is what an observer holds. ∎

**Corollary (the motivating ambiguity dissolves without any declaration).** «no anchor for this hour» and
«this publisher commits DAILY and the hour sits inside a covered day» differ on `covered(w, Γ)`, which the
observer computes. The granularity is READ, exactly as the window fields were designed to allow, and a coarser
committer is not mistaken for a silent one.

**Theorem F.5q-d (exactly one question survives, and it is present-tense).** Let `T = to(head(Γ))`. The
proposition «a commitment is OWED now» is not measurable in `σ(Γ)`.
*Proof.* Fix `Γ`. Two publishers with identical chains differ in whether another commitment is due: one
promised a rhythm and is late, the other promised none and is exactly where it intends to be. The chain is
byte-identical in both worlds, so no function of it separates them. ∎ This is F.5p.2 on the anchoring axis —
silence is `on-time ⊔ late` until one positive statement of intent separates them.

**So a declared commitment cadence is a CAPABILITY buying exactly `F.5q-d`, and nothing below it.** It does not
gate `covered`, `gap`, validity, inclusion, or any document verdict; a publisher that declares no rhythm loses
none of them. This matters beyond tidiness: a grid-driven publisher is the exception. An event-driven one — a
business stream, where commitments follow occurrences rather than a clock — has no rhythm to declare and must
not be treated as deficient for it. **Nothing is owed where nothing was promised**, and the floor is therefore
`no-rhythm-declared`: a settled state, never a pending one (F.5p's two facts, applied to the declaration
itself rather than to what it describes).

**Binding: realized (the CHAIN half; the DECLARATION member landed with F.5p.3)** — *"F.5q-c an hour INSIDE a daily commitment is covered — the granularity is READ from the window fields, so a coarser committer is not mistaken for a silent one, and no declaration is consulted"* · *"F.5q-c a window OUTSIDE every commitment is uncovered, and that is a different answer from the covered one — the ambiguity this dissolves is exactly these two being one observation"* · *"F.5q-c a MISSING window between two commitments is measurable in the chain alone — the discontinuity is a function of fields the documents carry, with nothing declared anywhere"* · *"F.5q-c an EMPTY chain answers `unknown`, never `uncovered` — a chain nobody supplied is not evidence that a window is unanchored"* · *"F.5q-c the coverage report is TOTAL — a chain fetched from a mirror is untrusted input, so hostile members yield a report rather than an exception"*.

**The DECLARATION half is deliberately not built, and the residual is named rather than implied:** F.5q-d needs a
clock, and a clock reached through an argument is a verdict-flip — it waits until it can be verifier-owned. The
`no-rhythm-declared` floor and the proof that declaring changes no verdict below F.5q-d land with the profile
member, thelabmd/UST-Protocol#127. Everything the chain settles is settled now; nothing about it waits on a
publisher promising anything.

**Conformance (math ⇒ spec ⇒ code ⇒ green vector, once realized).**
- `covered` and `gap` are computed from the chain with NO declaration supplied, and answer;
- a publisher declaring no rhythm is reported as `no-rhythm-declared` — settled, distinguishable from a declared
  rhythm currently silent;
- declaring a rhythm changes no verdict below F.5q-d.

### F.5p.3 A declaration must be AUTHENTICATED exactly when it can earn a pass

Two declared rhythms now exist in this protocol and they sit on opposite sides of a line that must be stated,
or a later reader will "fix" the inconsistency by making them alike.

**Theorem F.5p.3 (signature is required by pass-earning, not by subject).** Let `D` be a declaration and `V(D)`
the verdict function it feeds. If there exists `D'` such that `V(D') ≻ V(D)` — some declaration yields a
STRICTLY stronger verdict than another over the same artifacts — then `D` is an assurance-bearing input and
MUST be authenticated: an unauthenticated `D` lets the party under judgement choose its own verdict, which is
F.5a.1. If instead `V` is monotone in obligation — every declaration can only ADD checks the publisher must
pass, and the undeclared case is the weakest — then no `D'` improves the verdict and authentication is not
required for soundness. ∎

**The two rhythms, classified by that test rather than by name.** The §11.3 stream cadence decides
`complete` — the no-omission rung — so a publisher free to shrink its grid would declare away the slots it
missed and EARN the top rung; it is signed, `prev`-chained and resolved at a slot's time, and must be. A
commitment cadence buys only F.5q-d, and by F.5p's monotonicity a coarser declaration exposes the publisher to
FEWER checks and grants nothing: an anchor that is present counts whether or not it was declared. It therefore
needs no signature, and belongs with the substrate declaration.

**Corollary (and this is the load-bearing half).** Sufficiency is not the protocol's to coerce. A consumer that
needs a rhythm finer than one declared sets its own floor (R2/R4); the protocol's job is to make the
declaration and its absence DISTINGUISHABLE, never to require one.

**Binding: realized** — *"F.5p.3 declaring a rhythm moves NOTHING else in the closed half — it can only add an obligation, never earn a verdict, so every other member reads exactly as it did undeclared"* · *"F.5p.3 a member the reader does not implement is still REFUSED — a binding key silently dropped is an obligation relocated into a channel no verifier reads"* · *"F.5p.3 and the refusal NAMES the reader as the party whose reach ran out, not the publisher — a ruleset this build lacks is outside the sentence a finding against the operator makes"* · *"F.5p.3 ADVERSARIAL a MALFORMED KNOWN member is still the publisher's — the attribution splits on whether the reader lacks the rule, never on the mere fact of a refusal"*.

**The attribution half was a live defect and is recorded as one.** MEASURED before this round: an unknown member
of the closed half reported `fail` against the OPERATOR, so the first publisher to declare a newer member would
be called broken by every older reader — round 165's finding, one surface over, on the surface whose whole
purpose is to be extended.

**Conformance (math ⇒ spec ⇒ code ⇒ green vector, once realized).**
- an unsigned stream-cadence change is REFUSED, and the signed one resolves;
- a declared commitment rhythm never moves a verdict upward on any axis;
- both are reachable from a publisher that declares only one of them.

## F.5r A producer with a PRIVATE head cannot see its own fork — and downstream detection is not guaranteed to happen (#122)

The consumer side of this is already closed: `verifyStream` refuses two frames sharing a `prev`
(**two frames share a prev**, `E-PREV`, Y1). What follows is about the OTHER side — the
appender — and about a gap between the two that the existing check cannot close.

**The setup.** Let a stream be a sequence of documents where `dₜ₊₁` carries `prev = h(dₜ)`, so the
stream's identity at any moment is its head `Hₜ`. An appender must READ `Hₜ` to write `dₜ₊₁`. Write
`I_A` for the information available to appender `A`: the documents `A` itself produced.

**Theorem F.5r-a (producer blindness).** If the head is private to the appender, fork-freedom is not
measurable in `I_A`.
*Proof.* Fix `A` starting from `H₀`. In world 1, `A` alone appends and produces `d_A`. In world 2, a
second appender `B` — same genesis, same key, its own private `H₀` — also appends, producing `d_B`
with the same `prev`. `B`'s writes never enter `I_A`. The observation sequence of `A` is IDENTICAL in
both worlds, so no function of `I_A` separates them, and `A` cannot refuse what it cannot see. ∎

Both documents are individually VALID: each is well-formed, signed by an admitted key, and chains to
a real predecessor. The defect is not in either document; it is in the PAIR, and neither producer
holds the pair.

**Theorem F.5r-b (downstream detection does not happen at all — measured, not assumed).** A fork is
not two frames in one sequence; it is TWO SEQUENCES, each linear and each clean.
*Proof.* Let `d_A` and `d_B` share `prev = h(dₜ)`. Present them to a range verifier in one array and
the chain check fires FIRST — the second frame's `prev` no longer equals the running head, so the
verdict is `frame i prev dangling (broken chain)`, not a fork. Reorder them and the chronology check
fires instead. Present each branch alone, as a consumer actually receives it, and each verifies
CLEAN: one `prev` per frame, a linear chain, a correct verdict on the evidence seen. There is no
input under which the two branches are reported AS A FORK. ∎

**Correction (rev73 — this section first claimed the opposite, and the vacuity battery refuted it).**
The original text said `verifyStream` catches two frames sharing a `prev`, citing its `seenPrev`
guard, and the conformance check asserted `error === 'E-PREV'` — which passes whether the fork guard
fires or the dangling guard does, so the claim was never tested. Tightening the assertion to require
the word *fork* in the detail turned the check RED on a clean tree: the guard is dominated by the
chain check standing before it and is unreachable for any input. A guard that cannot fire is not a
detector, and a specification resting on it is resting on nothing.

**Corollary (the refusal has exactly one home).** Since no consumer can be shown the fork, and the
producer with a private head cannot see it either (F.5r-a), a fork produced this way is invisible
EVERYWHERE. That is not a weaker version of "detection is conditional" — it is the stronger claim,
and it removes the option of leaving this to the verifier.

**Where the refusal has to live.** The only party positioned to observe both attempts is whoever
writes the head, so fork-freedom must be enforced there — which requires the head to be SHARED among
appenders rather than private to each. Nothing downstream can compensate: the branches never meet.

**And what a shared head actually buys, stated honestly.** Two mechanisms, two different claims:

| store contract | what it yields |
|---|---|
| `get` / `set` | **DETECTION.** Between `A`'s read and `A`'s write, `B` may write. The race is not closed; the next append notices the head moved and can refuse then. |
| compare-and-set | **PREVENTION.** The write is conditional on the head still being what was read, so only one of two concurrent appends lands. |

The distinction is load-bearing and must not be blurred: a layer offering `get`/`set` that claims to
PREVENT forks is claiming a guarantee it does not have — the same class as reporting an unattestable
property (F.5o) or a universal claim over an undeclared domain (F.5q). It must say which one it got.

**Theorem F.5r-c (the guard belongs to the KEY, not to the method).** Let `W = {w₁ … wₙ}` be the set
of operations an implementation offers that WRITE the head key. Fork-freedom holds iff EVERY `wᵢ`
applies the guard.
*Proof.* Suppose some `w_j` does not. Two appenders `A`, `B`, both invoking `w_j` from head `H`:
neither write is conditioned on the stored head, so both land and the branches are produced exactly as
in F.5r-a. The guards on the other `n − 1` operations change no observation in this scenario, because
they were never invoked. Hence the guarded FRACTION is irrelevant; the outcome is determined by the
unguarded operation alone, and an implementation with `n − 1` guarded writers is exactly as forkable as
one with none. ∎

**Corollary (what a conformance check must therefore enumerate).** A check naming ONE guarded
operation attests nothing about `W`: it is satisfied by an implementation in which every OTHER member
of `W` is unguarded. The obligation is to derive `W` FROM THE SOURCE — every site that writes the head
key — and to show `W` reduces to the guard itself. Naming an instance where the claim quantifies over a
set is the same failure as F.5q's quantifier over an undeclared domain, one layer down.

**Measured (rev75).** The layer that introduced the guard had `n = 3`: `append` (guarded, and the check
named it), `gap` — the §11.1 signed gap record, which extends the chain exactly as an append does — and
`resume`. Both of the latter wrote the head directly. Two instances each emitting a gap record forked
silently, and the check written one round earlier stayed green throughout, because it asserted a
property of `append` while the specification quantifies over writers.

**CLOSED 2026-08-01 by rev75 (`7f6a123`) — the same revision the measurement names, noted here 2026-08-05.**
The guard moved from the METHOD to the KEY, so every writer of a head passes it rather than the one writer
someone remembered to guard. The paragraph above is kept as the evidence the theorem rests on, not as an
outstanding defect.

**Admissibility of an EXTERNAL head claim (`resume`).** Resumption states a head from knowledge outside
the store — an operator's assertion, not an observation. It is nonetheless a member of `W`, so it is
admissible iff the stored head does not CONTRADICT it: `stored ∈ {⊥, H}`. A stored head differing from
`H` is precisely the disagreement the discipline exists to name — another writer has been advancing —
and overwriting it is the fork-causing act, not a repair of one.

**Theorem F.5r-d (one event, one door — and its internal order is forced).** Writing a frame moves
THREE stored values: the head `H`, the cumulative count `C`, and the observed interval `S`. They are
not three facts; they are one fact recorded three ways, and a store offering no transaction cannot
write them simultaneously. Two consequences follow.

*(i) The guard precedes the rest.* If `C` or `S` is written before the head guard runs, a REFUSED
frame has already moved them: a stream that correctly refused to fork nevertheless counts a frame it
never emitted, and its next stream checkpoint asserts coverage over a document that does not exist. The
guard must therefore be the FIRST write of the group, so a refusal leaves the whole group untouched.

*(ii) A partial write must land on the UNDER-claiming side.* Suppose the process stops between two of
the three writes. If `C` lags the frames, the publisher claims FEWER frames than it delivered; if `C`
leads, it claims MORE. Both are permanent — `C` is cumulative, so every later stream checkpoint carries the
error — and both are detectable. They are not equally safe: an over-claim asserts a frame that was
never emitted, and "a frame is missing" is precisely the signal that means data was WITHHELD, so the
publisher manufactures evidence of an omission it did not commit. An under-claim never conceals one.
Hence the order `H` then `C`, and the door that writes them must not be split into parts a caller can
invoke separately — a caller who advances the head and forgets the count reproduces exactly the
over-claim this ordering exists to avoid, only silently.

**Corollary (what the layer must expose).** Not one door per VALUE, but one door per EVENT: a frame
entered the stream, and an interval was sealed. A finer surface is not more flexible, it is more
forkable — the operator becomes responsible for an ordering the layer already knows.

**Measured (rev76).** The first operator kept these values in two different call sites — the head
moved in the publish path, the count and the interval in a post-write hook — which is how the head
came to be advanced AFTER publication (F.5r, rev74) without anything noticing: no single place held
the group, so no single place could state its order.

**Theorem F.5r-e (an absence the substrate cannot represent is not an absence).** The layer owns a value
whose lifecycle includes being UNSET — the start of the open interval, cleared when the interval is
sealed. Absence is not a value, and a store's value domain need not contain a representation of it.
*Proof by the failure it permits.* Encode absence as a sentinel `σ` and clear by writing `σ`. If the
substrate rejects `σ`, the write does not land and a subsequent read returns the STALE value. The layer
then reads a value it believes it cleared, so the next interval never opens and the following seal
asserts bounds that BEGIN BEFORE the interval it covers — the exact over-claim F.5r-d forbids, produced
by the mechanism meant to prevent it. ∎

**Measured (rev77), in production, within an hour of shipping.** `recordCheckpoint` cleared the interval
start by writing the empty string. The reference operator's store is a REST key-value service whose
path-form `SET` has no representation for an empty value: it answered `400 ERR wrong number of arguments`.
The seal reported success, the interval start still held the previous hour's first `ust_id`, and the next
seal would have claimed an hour beginning sixty minutes before itself.

**Corollary (the port must carry the lifecycle, not a hope about round-tripping).** A value the layer
clears requires a CLEARING OPERATION in the port contract — `del` — not a sentinel the layer assumes
survives. A store that cannot delete cannot implement an interval lifecycle, and the layer must say so
rather than proceed on a write it cannot confirm.

**Corollary (an error that is not an exception).** The same measurement exposed a second failure of the
same shape one layer down: the operator's port reported failure only for THROWN errors, so a `400`
response was indistinguishable from success. "Fail loud" is a claim about the failure MODES a substrate
actually uses, not about the ones a caller finds convenient to catch.

**Theorem F.5r-f (a single writer forks itself, and the guard is blind to it).** The guard of F.5r
compares the head a writer OBSERVED against the head the store HOLDS, and refuses when they differ. That
decides one of the two ways a head acquires two successors. It cannot decide the other.

*The sequence.* A publisher whose substrate offers no transaction across "publish" and "record" must
order them, and F.5r-e's measurement forces publish-first: recording first leaves the head naming a
document that was never published, so every consumer walking the chain arrives at nothing. Then let
writer `A`, alone, from head `H`:

1. `A` reads `H`, builds `d`, PUBLISHES `d`;
2. the write of `h(d)` FAILS — a timeout, a 5xx, or the process ending between the two steps;
3. next interval, `A` reads `H` again, builds `d'` with `prev = H`, publishes `d'`.

`d` and `d'` are two successors of `H`, both published, both individually valid: the F.5r fork, with no
second writer anywhere.

*Blindness of the guard.* At step 3 the guard evaluates `expected = H` against `stored = H`. They are
equal, so it accepts. The guard is SOUND — it answers exactly the question posed — and the question was
incomplete: it asks whether somebody else advanced the head, never whether THIS writer's own advance
landed. No refinement of the comparison repairs this, because both operands are correct. ∎

**Corollary (where the missing information lives).** By F.5r-b neither branch is ever reported as a fork
downstream, and by F.5r-a the head being shared does not help, since it was never contested. The one
party holding the discriminating fact is `A` itself, and the fact is not in the store: **`A` knows what
it published.** The predicate that decides step 3 is `stored = h(d)` where `d` is the document this
instance last published — a comparison between the store and the writer's own emission, not between the
store and the writer's earlier reading.

**Corollary (asymmetry of the repair).** Re-asserting `h(d)` after a failed write is IDEMPOTENT: it
names the same successor of the same predecessor, so a retry is not a second advance and carries no risk
of overwriting a legitimate later head — the guard's own comparison still refuses if the store has moved
on to something that is neither `H` nor `h(d)`. The two failure directions are therefore not
symmetric: retrying a lost advance is safe, while proceeding past one is the fork itself.

**Corollary (what a process that died cannot do).** Retry alone is insufficient. A process ending
between steps 1 and 2 has no retry left, and its successor — the next process, or another instance —
reads a head that disagrees with the published set without holding the emission that would reveal it.
Recovering that requires reading the PUBLISHED set rather than the writer's memory, which is a
substrate capability, not an inference: an operator that can enumerate what it published can compute the
true head; one that cannot must say its head is unverified rather than assume it.

**Theorem F.5r-g (the stored head is a CACHE; the published set is the fact).** F.5r-f leaves one case
open: a process that ends between publishing and recording takes its emission with it, so its successor
holds no discriminator and must answer `unverified`. That answer is honest but not final, because the
discriminating information did not vanish — it was PUBLISHED.

*The stream's head is defined by what exists, not by what is remembered.* A consumer walking the chain
reads documents; it never reads the producer's pointer. The pointer is therefore a cache of a fact whose
home is the published set, and a cache disagreeing with its source is wrong rather than authoritative.

**The head-recovery, and why one document suffices.** Let `d` be the LAST document the publisher published and
`H` the stored head. `d` carries `prev`, so:

| observation | what it proves | action |
|---|---|---|
| `H = h(d)` | the pointer already names the published head | consistent |
| `H = prev(d)` | `d` EXTENDS what the pointer names — the advance was published and not recorded | adopt `h(d)` |
| `H = ⊥` | nothing was ever recorded | adopt `h(d)` |
| otherwise | `d` neither is nor extends what the pointer holds | REFUSE — unverifiable |

The second row is the whole point: `prev(d) = H` is a PROOF, carried in the document itself, that `d` is
the successor of the head the pointer still names. No trust in the reader's memory, no comparison against
a timestamp, no assumption about which of two writers ran last. ∎

**Why the last row must refuse rather than adopt.** Adopting a published head that does not extend the
stored one would take the stream from whoever legitimately holds it: if another writer advanced past `H`
and the document read here is an older one, adopting it would chain the next frame beneath a live branch —
manufacturing the very fork F.5r prevents. A disagreement this head-recovery cannot explain is a disagreement
it must not resolve.

**What the layer may and may not do.** Reading the published set is a SUBSTRATE capability: an operator
that can enumerate or address its own published documents supplies the last one; the layer verifies the
`prev` relation and decides. A layer that fabricated this capability — guessing at the head, or trusting
the pointer because it is convenient — would be asserting a fact it cannot observe, which is the failure
class of F.5o. Where the capability is absent, `unverified` remains the correct answer and must be said
rather than assumed.

**Bounded search.** The publisher's own addressing gives the order: documents are addressed by `ust_id`,
a time coordinate, so "the last published document" is found by walking the declared cadence grid
backwards from the present. The search MUST be bounded — an arbitrarily long outage would otherwise turn
a restart into an unbounded scan — and exhausting the bound is `unverified`, not failure: an interval with
no published document in the searched window is a GAP, and a gap is stated by a §11.1 record, not inferred
by a reader.

**Corollary F.5r-g.2 (head-recovery is the FRAME EVENT, not the repair of one field).** Adopting the published
document `d` is not "setting the head to `h(d)`" — it is the stream ACCEPTING `d`, which by F.5r-d moves one
GROUP: the head, the frame count, and the interval bound. Moving a proper subset leaves the stream describing
two different documents at once. The consequences are not symmetric: an under-counted stream under-claims,
which F.5r-d already establishes as the safe direction, while a stale interval bound is UNSAFE — §9 requires a
stream checkpoint's `to` to be the last frame's `ust_id`, so an interval sealed after a partial head-recovery does
not bound its own set and a consumer answers `E-PREV`.

*Measured (2026-08-02, reference operator).* Head-recovery moved the head alone. The first reader of the pair — a
gap backfill, which measures a hole FROM the interval bound — found a document occupying the slot where the
bound said the next one began, and correctly refused to declare a gap over it. The document was the operator's
own, the one the head had just adopted. The defect was invisible to every check that read the head, because the
head was right; it surfaced only where two members of the group were read TOGETHER. That is the general shape:
a group split across writers is detected by whoever reads the pair, and until someone does, each half looks
correct.

**Corollary F.5r-g.1 (the outcome set is TOTAL, and it belongs to the layer).** The four observations in
the table above partition every input: the stored head either equals `h(d)`, equals `prev(d)`, is absent,
or is none of these, and no document is supplied at all in the remaining case. Nothing falls outside, and
nothing lands in two.

A total set of outcomes is an INTERFACE, not prose. Two operators reporting the same situation must emit
the same word, or their telemetry cannot be compared and neither can their incident reports — the same
argument that put the state KEY NAMES in the layer rather than in each operator. Measured 2026-08-01: the
first operator to adopt this minted `refused` for the refusal, because the layer named the three states it
RETURNS and left the one it THROWS unnamed. A vocabulary with a hole in it gets filled locally, and then
two operators disagree about a case they both handle correctly.

**CLOSED 2026-08-01 by rev80 (`8a46355`), noted 2026-08-05.** The layer therefore declares the COMPLETE set,
refusal included, and an operator reports one of those words rather than one of its own. The prose around it may be in any language; the STATE is a token.

**Theorem F.5r-h (UNKNOWN is not ABSENT, and an origin frame is a CLAIM).** A frame carrying no `prev`
does not merely omit a field. It ASSERTS that the stream begins here — that no earlier frame exists for a
verifier to demand. Emitting one is therefore an act of knowledge, and the knowledge it requires is
exactly `H = ⊥`.

*The failure.* Let a producer read its head through a port whose signature is `get(key) → value | null`.
That type has two inhabitants where the producer needs three: a value, a definite ABSENCE, and an
UNREADABLE state. A port that answers `null` on a failed read collapses the second and third, and the
producer — reasoning correctly on what it was told — emits an origin frame in the middle of a live stream.

*What that produces is worse than a gap.* A gap is an absence: nothing exists, and a verifier computing
the cadence grid sees a hole it can name. An origin frame emitted from ignorance is a signed, individually
VALID document that belongs to no chain: nothing references it and it references nothing. It is
indistinguishable, to every consumer, from a legitimate stream-genesis — so the stream now appears to have
two beginnings, and the earlier one cannot be reached from the later. ∎

**Corollary F.5r-h.1 (a stream verifier DOES distinguish — and why this guard stands alone).** The theorem's
"indistinguishable, to every consumer" is a claim about the DOCUMENT, and as such it holds: an origin frame carries
nothing that separates it from a legitimate stream-genesis. What a consumer verifying a SEQUENCE distinguishes is not
the document but its POSITION. Within a set of frames offered as one stream, a frame after the first that carries no
`prev` contradicts a head the set has already established, and MUST be refused (`E-PREV`). The harm of an origin frame
emitted from ignorance is therefore BOUNDED to consumers reading documents in isolation; to anyone verifying the stream
it is not a second beginning but a refusal.

*Why this guard has no backstop, and why that is structural rather than an oversight.* Every other linearity guard
compares VALUES — `prev` against the running head, `prev` against the prevs already seen, `ust_id` against the previous
slot. An absent `prev` offers no value to compare, so a guard written over values cannot reach it. Measured 2026-08-10
against the reference implementation by removing guards one at a time: a same-slot sibling is refused by FOUR
independent guards and a stale-head repeat by TWO, but a mid-stream origin frame by exactly ONE — the shared-prev guard
reads `if (p && …)` and skips a frame with no `prev` entirely. The presence check is thus not derivable from the value
checks and not redundant with them; an implementation that omits it ADMITS the frame this theorem is about.
The single guard is **STANDING by construction**, not an open hole: a presence test is the only shape that reaches
an input carrying no value, so adding a redundant guard beside it would add no coverage. What WAS missing is
CLOSED (2026-08-10, round 198) — a vector making the omission visible to any implementation, since before it the
corpus would have accepted a build with this branch removed. ∎

**Corollary (the direction of the refusal).** Reading the head answers whether it is SAFE TO EXTEND, and by
the fail-direction rule such a question fails CLOSED: not knowing the head authorizes nothing — neither
extending a head one cannot confirm, nor claiming there is none. The interval is then unpublished, which
is a GAP, and a gap is stated under §11.1 rather than papered over with a document.

**Corollary (the obligation is on the PORT, not on the reader).** A reader cannot recover a distinction
its input never carried; no amount of care downstream separates `null`-because-absent from
`null`-because-unreachable. The port must signal an unreadable value distinctly — by raising rather than
returning — and a store adapter that swallows a read failure into `null` silently disarms every guard
built on top of it, including F.5r's own comparison, which reads `null` as "nobody has written yet" and
proceeds.

**Measured (rev82).** The reference operator's pointer read was `catch { return null; }`. Its guards were
correct and its head-recovery was correct; the input was a lie, and a lie at the port defeats both.

**Binding: realized** — *"#122 ADVERSARIAL: two appenders from one head both succeed when the head is PRIVATE — the fork is produced and neither can see it"*, *"#122 ADVERSARIAL: the two branches are NEVER reported as a fork — the chain guard fires first, so downstream detection does not happen"*.

The REFUSAL itself lives one layer up and is checked there, not here: `packages/ust-operator/conformance.mjs` exercises a shared store — a second appender on one head is refused `E-FORK`, a stream resumes the same chain in another object, and a `cas`-capable store reports `prevented` while a plain one reports `detected`. The core suite must not import the operator layer; a dependency in that direction would make the TCB's own tests rest on something above it, and I nearly wrote exactly that by citing an operator check in this Binding.

**Conformance (math ⇒ code ⇒ green vector, `packages/ust-protocol/conformance.mjs`).**
- the private-head case reproduces the fork and shows both branches individually valid.
- the shared-head case refuses the second appender, and the refusal names which guarantee it rests on.

## F.5s The stream FLOOR, and the one coordinate where suppression FORGES (#160)

`¬∃ state at t` looks like one claim and is two, split at the address where the identity began. Write `Addr` for
the ust_id space (§8, totally ordered) and `F` for the FLOOR — the address of the ROOT genesis of the identity's
epoch chain.

- `t < F` — the identity did not exist. The operator owes no coverage there, and any document addressed there is
  a RETROSPECTIVE claim, distinguishable by an anchor later than its address.
- `t ≥ F` — the identity existed and the slot is empty. A coverage fact, decidable only through §11.3.

So `F` is the boundary of the OBLIGATION domain, and that is what makes its direction of error asymmetric:

> a floor EARLIER than the truth is conservative — the operator answers for time before it existed.
> a floor LATER than the truth DISOWNS real gaps, reclassifying them as a world in which nothing was owed.

**Theorem F.5s-a (root-ness is authenticated non-membership).** The assertion that a held genesis is the ROOT is the proposition
`¬∃ transition into my epoch`. It is not decidable from the genesis document: measured, a genesis carries `pub`,
`role`, `max_partitions`, `max_transcript_bytes`, `cadence`, `checkpointAuthority`, `recovery`, `roles` — and no
predecessor reference of any kind. Nor is it decidable from a transition: `verifyEpochTransition` reads only
hashes (`from_genesis_epoch`, `to_active_genesis`) and never sees a genesis document.
*Proof.* Two histories: in `H₁` the held genesis is the root; in `H₂` an earlier epoch transitioned into it and
the transition is simply not in `ℐ`. Every byte the consumer holds is identical, so no function of `ℐ` separates
them. ∎ Hence the floor question reduces to the class F.5a treats — declaring an origin does not leave the
witness class, it relocates one level into it.

**Theorem F.5s-b (on this coordinate, suppression FORGES).** Let the consumer trace the chain back through the
transitions it was given and take the earliest reached genesis as the floor. A publisher that WITHHOLDS its
earliest transitions moves the derived floor LATER, and every gap in `[F_true, F_derived)` is thereby
reclassified from a coverage failure into a period in which nothing was owed.
*Proof.* Immediate from the split above: the reclassification follows from the boundary moving, and withholding
moves it in exactly one direction. ∎

**This inverts W1, and it is the only coordinate measured to do so.** Everywhere else in this model, removing
evidence from `ℐ` can only lower the decidable tier (F.5b, monotone erosion) — authority can be DENIED but not
fabricated. Here removal IMPROVES the publisher's answer. The reason is structural rather than incidental: every
other coordinate is a claim the publisher wants ADMITTED, so its evidence is something it supplies; the floor is
a boundary the publisher wants MOVED, and the evidence that pins it is something it supplies too. A negative
claim whose domain the claimant delimits is not bounded at all.

**Corollary F.5s-c (a publisher-supplied chain earns a CANDIDATE, never a floor).** By F.5s-b the chain's
completeness is the publisher's to withhold, so a floor derived from it alone is a self-delimited negative claim.
`F` is ESTABLISHED only when root-ness enters `ℐ` from outside the publisher's influence — a consumer-held root
(the `trust` pattern of §12.3.4) or, when it ships, the anchored map of F.5a. Otherwise the honest verdict names
the floor as UNESTABLISHED, with the missing coordinate reported through the F.5.1f absent set.

**Corollary F.5s-d (a partial trace supplies no usable bound EITHER WAY).** One might hope a partial trace at
least bounds `F` from above. It does not: the bound `F ≤ X_k` needs genesis addresses to be monotone along the
chain, and `verifyEpochTransition` cannot observe an address at all, so nothing enforces it. Reporting a partial
trace as a dated floor is therefore wrong twice — the direction is unsafe, and the bound is unproven.

**Realization (rc.72 line, REV 71).** `deriveStreamFloor` walks the supplied transitions to a candidate root,
binds a supplied root genesis to it by `genesisEpoch(contentHash(·))`, and returns `established: true` ONLY when
that root is also consumer-admitted; otherwise it returns the candidate under its own name with root-ness named
as the missing coordinate. Deliberately NOT done: address monotonicity in the transition check, which would buy a
bound for a question no surface asks, at the price of editing a signed form.

**Conformance.**
- Theorem F.5s-a: *"F.5s a genesis carries no predecessor — root-ness is not decidable from the document"*.
- Theorem F.5s-b: *"F.5s withholding the earliest transition moves the derived floor LATER (suppression forges)"*.
- Corollary F.5s-c: *"F.5s a publisher-supplied chain earns a candidate, never an established floor"*.
- Corollary F.5s-c, the established half: *"F.5s a consumer-admitted root establishes the floor"*.

## F.5t The NAME is a claim, and an unverifiable one is worse than none

A consumer decides whether to verify an artifact by reading how it identifies itself. An artifact carrying
the protocol's name tells a machine to APPLY THIS PROTOCOL'S VERIFIER. That is an instruction, not a
decoration, and it is read mechanically — before any documentation, by a party that has none.

**Theorem F.5t (a label that fails verification is indistinguishable from a damaged document).** Let `A`
be an artifact carrying the protocol name and not conforming to it. A consumer applies the verifier and
gets a failure. MEASURED, that failure is `INVALID: E-MALFORMED` — the same verdict AND the same error code
a TRUNCATED or CORRUPTED document produces. Nothing in the observation separates NEVER-A-DOCUMENT from
ARRIVED-DAMAGED, so a benign artifact emits the signal of a broken transfer. ∎

*Stated at the strength the measurement supports, and no further.* A TAMPERED document — one whose bytes
were altered after signing — answers `E-CANON`, so the labelled non-document is distinguishable from
forgery and NOT from damage. The weaker claim is the true one and is sufficient: a consumer that retries a
"damaged" fetch, alerts on corruption, or quarantines the source is responding to an incident that never
happened.

**Corollary (the exception list is the divergence).** A consumer that learns to special-case the artifact
must carry a private list of things that wear the name and must not be verified. Two consumers' lists
differ, and an artifact absent from one list fails there while passing here — the protocol's whole purpose
is to remove exactly that class of private knowledge.

**Corollary (there are two honest options, and no third).** Either the artifact IS a document of the
protocol, or it does not carry the name. "Carry the name and document the deviation" is not available: the
label is read by machines that never read the documentation. Companion files that plainly are not
documents — timestamp proofs, indexes, manifests — do not carry the name and raise no question.

**Corollary (and the cost falls on the party that is trying to be honest).** The artifacts most likely to
be labelled loosely are the ones an operator publishes to be TRANSPARENT — incident records, evidence,
mirrors. So the failure lands precisely where the operator was doing something right, and turns a mirror
full of evidence into a mirror full of unverifiable claims.

**Binding: realized** — *"#115 F.5t ADVERSARIAL a labelled NON-DOCUMENT is INDISTINGUISHABLE from a damaged one — same verdict AND same error code as a truncated document, so a benign file emits the signal of a broken transfer"* · *"#115 F.5t an artifact WEARING the protocol name and lacking state/sig does NOT verify — the label is an instruction to apply this verifier, and it is obeyed"*.

And a GATE beyond them, because the theorem has a second subject the conformance suite cannot reach: not the
verdict a document produces but the set of artifacts a tree PUBLISHES. `tools/protocol-name-gate.mjs`
examines every artifact wearing the name, judged by DOCUMENT SHAPE rather than by directory, verified in the context its
own `class` demands; a negative sample's expectation is read from its recipe rather than from a list inside
the gate, since a gate carrying its own exceptions is the private knowledge this theorem is about. A floor
on the examined count keeps the roster from going blind, and a planted unsigned artifact proves the gate
can fail.

**Measured (rev83). The MECHANISM closed 2026-08-04 (rev107, F.5t-a); the operator's own set has not.** Noted
2026-08-05, after an extraction agent read the paragraph below and reported it as a live defect in this tree.
What closed: the obligation quantifies over the set an operator PUBLISHES, so the predicate moved into the
package and ships as an operation a publisher runs over its own artifacts — the rule no longer binds a party
that holds no procedure. What has not: measured on the reference operator's public mirror the same day, 1046
artifacts wear the name and exactly one is a document. That is the operator's remediation, tracked on its side.

**Measured (rev83).** The reference operator's outage records — the independent evidence its own gap
records were about to cite — carry `"protocol": "UST"`, no version, no `state`, no signature. Their
integrity rests on an append-only log and a timestamp proof, which establish TIME and EXISTENCE and say
nothing about authorship. Citing them as evidence in one's own favour is therefore self-attestation with
extra steps, and the label made it look like more.

### F.5t-a The obligation is a property of a SET, and a verifier is a function of ONE document

F.5t binds a PUBLISHER, and the shape of that binding decides who can ever discharge it. Write the obligation
as `∀a ∈ Pub(o). name(a) ⇒ doc(a)`, quantified over `Pub(o)` — the set of artifacts an operator `o` publishes.

**Theorem F.5t-a (no consumer-side observation establishes the name obligation).** A verifier's domain is a
single artifact: `V(x̂, ℐ_v, ρ_v) ↦ verdict` (R2), and `Pub(o)` is not among its inputs. A consumer that
verified every artifact it has ever fetched has established the predicate on a subset it did not choose, and
the artifacts it never fetched are precisely those that could falsify it. Enlarging the sample does not change
the quantifier. The only party whose information contains `Pub(o)` is `o` itself. Hence the obligation is
discharged by a PRODUCER-side enumeration over `Pub(o)`, or by nobody. ∎

**Corollary (a rule whose decision procedure exists only in the rule-maker's tree is unenforced where it
binds).** The procedure that decides `name(a) ⇒ doc(a)` may enumerate a domain. If the only implementation
enumerates the PROTOCOL's own tree, then the party bound by the rule — every operator — holds no procedure at
all and can comply only by inspection. Inspection over an unbounded published set is not a decision procedure,
so the rule holds normatively and is unenforced in the one place its violations occur. This is the general
form of the failure F.5q names for observation: quantifying over a set nobody enumerated.

**Corollary (the honest options are two, and shipping the procedure is what makes the second reachable).**
F.5t leaves an operator either not wearing the name or being a document. An operator cannot choose the second
deliberately without being able to ask which of its artifacts already fail it. So the procedure is not a
convenience built beside the rule; it is the term that makes the rule's own disjunction decidable by the party
the rule is addressed to.

**Binding: realized** — *"F.5t-a a labelled NON-DOCUMENT inside a target SET is REPORTED, and named BY ITS id — a tally without the offending member is a number an operator cannot act on"* · *"F.5t-a a set whose named artifacts ARE documents is NOT reported — the rule forbids wearing the name without being a document, never wearing it"* · *"F.5t-a examining NOTHING is not a pass — an empty target set is its own outcome, never folded into compliance"* · *"F.5t-a a set that examined artifacts and found NONE wearing the name is distinguishable from one that examined none — four outcomes, never three"* · *"F.5t-a an artifact that wears the name and cannot be PARSED is reported, not skipped — an unreadable member is the case the rule is about, not an exemption from it"* · *"F.5t-a the SET report is TOTAL — hostile or malformed entries yield a classification, never an exception, because the caller is a directory walk and not a curated list"*.

And the surface, because a procedure nobody can point anywhere is the corollary again one level up: `ust names
<paths>` walks a target set offline and reports the four outcomes. The tree gate that was formerly the only
implementation now CALLS the export rather than holding its own copy, so an operator's sweep and this
repository's sweep decide the same question the same way.

## F.5u A root is published TWICE, and only one of the two publications can enumerate (#127)

Fix the hash `H` and the §7 Merkle construction over a leaf multiset `L`, with `r = root(L)`. Two DIFFERENT
assertions about `r` occur in this protocol, and the protocol until now gave a document form to only one:

- **Seal** `Σ(L)` — the claim that L is exactly this set and `r` is its root. The §9.2 `set` attestation.
- **Commitment** `Γ(r, W, σ)` — the claim that this signer committed `r` to substrate σ during window `W`.
  The batch root of §11, the object a timestamp proof is actually taken over.

**Theorem F.5u.1 (enumeration is neither necessary nor sufficient for membership).** The §11.2 inclusion
predicate is `Incl(d, r, π) = [ walk( H("ust:leaf", content_hash(d)), π ) = r ]`. `L` does not occur in it.
Hence (a) a consumer establishing that `d` is under `r` never reads an enumeration — it is not an input; and
(b) an enumeration establishes only `root(L') = r` for the list `L'` the publisher CHOSE, which is
self-consistency; to learn `L' = L` a consumer must enumerate the world, which the list does not do. The
enumeration therefore serves neither the inclusion use nor the audit use. ∎

**Theorem F.5u.2 (enumeration is a disclosure, and for a batching operator a forced one).** A batch exists to
amortise one substrate commitment over documents of MANY principals. Publishing `L` hands every reader a
membership ORACLE: any party holding a candidate document `d` may test `content_hash(d) ∈ L` without
possessing a path. Under `Γ` alone that capability belongs only to a holder of `π`. Where the members belong
to distinct principals, the disclosure is cross-principal and is not the committing operator's to make.
So a form that requires `Σ` in order to publish `r` is, for such an operator, not costly but UNAVAILABLE. ∎

**Theorem F.5u.3 (non-self-inclusion — a commitment is never inside what it commits to).** Let `Γ` carry
`provenance.root = r` and let `c = content_hash(Γ)`. Since `root` is inside the signed State, `c = f(r)`.
If `c ∈ L` then `r = root(L) = g(c)`, so `c = f(g(c))` — a fixed point of a composition of `H`, which we may
not construct. Hence `c ∉ L`. ∎

*Corollary (the head of a commitment stream has no anchored time of its own).* `Γ`'s own un-backdatable time
can come only from a STRICTLY LATER batch. A consumer reading the commitment stream at its head therefore
holds an element whose time is not yet established, so order and completeness AT THE HEAD cannot be recovered
from anchors and must be carried structurally — which is why `prev` is required of a commitment and not
merely available to it.

**Theorem F.5u.4 (a size claim in a commitment is refutable in the wrong direction).** Let `Γ` claim `|L| = n`
against a true `m`. If `m > n` a party holding `n+1` distinct valid paths to `r` refutes the claim. If `m < n`
no set of paths refutes it: showing that NO further leaf exists requires the whole tree, which no path
conveys. The claim binds an understating publisher and never an overstating one — it is refutable exactly in
the direction that is honest. Hence a count in a commitment carries no verification weight and MUST NOT be a
verification input. ∎

**Corollary (the same field is safe in one subtype and unsafe in another, because the safety was never in the
field).** `frame_count` in a stream checkpoint is safe DOWNWARD (F.5r-d: under-claim is the safe side) because
coverage is checked against an enumerable grid — the consumer can list what the interval should contain. A
batch has no such grid, so the identical-looking field flips from safe-downward to unsafe-in-both-directions.
The property belonged to the GRID, not to the counter; a field carried across a subtype boundary does not
carry its guarantees with it.

**Binding: realized** — *"F4b prev-only subtype vocabulary is TOTAL in the corpus — every runtime name admitted AND refused by a vector"* · *"subtype-anchor-with-root"* · *"subtype-anchor-no-root"* · *"subtype-checkpoint-with-root"* · *"subtype-pair-checkpoint-gap"*.

F.5u.1/F.5u.2 are realized by admitting a prev-only `anchor` subtype whose `root` is REQUIRED and whose
`constituents` are ABSENT (§9.2 C2, §11.3). F.5u.3 and F.5u.4 are realized as REFUSALS rather than checks, and
the distinction is the honest one: a commitment naming itself among its own constituents is UNCONSTRUCTIBLE —
there is no document for a verifier to reject, so a check asserting its absence would be vacuous — and a count,
where an operator carries one, is a LABEL in the sense of §9.1 that no verifier reads, so its realization is
the ABSENCE of a code path, which the capability roster records rather than a check.

## F.5v A declared absence is the STRONGEST statement that nothing was observed — so it may never back a no-event claim (#115)

Two mechanisms of this protocol are each sound alone and, composed, produce a false negative. F.5p separated
“not offered” from “offered and unreachable”; this is the same shape one layer down, and it bites in the
permissive direction.

**Setting.** A no-event claim over a window `W` is graded by the backing of the stream that covers it. A grid
slot `g ∈ W` is COVERED in exactly two ways (§11.3): a slot-bearing frame with `ust_id = g`, or a signed **gap
record** declaring that no frame exists for `g`. Both make the interval `complete`; only the first involves an
observation.

**Theorem F.5v (coverage is not observation, and a gap record is the publisher's own disclaimer).** Let
`Cov(W)` be the covered slots and `Obs(W) ⊆ Cov(W)` those where the publisher POSITIVELY observed. A gap record
at `g` is a signed statement by the publisher that it produced no frame for `g`; hence `g ∉ Obs(W)` **by the
publisher's own assertion**, not by inference. Therefore `Obs(W) ⊊ Cov(W)` whenever any gap record lies in `W`,
and grading such a window `completeness-backed` — defined as *every covered slot positively observed* — asserts
an observation the publisher explicitly disclaimed. ∎

*Corollary (the error is permissive, and it inverts the purpose of the record).* A gap record exists to make an
absence HONEST: it converts an unexplained hole into a declared one. If that same record also strengthens a
negative claim, then the more honestly a publisher reports its outages, the stronger its “nothing happened”
becomes — the mechanism pays the publisher for the very blindness it was built to confess. The correct grading
is `observation-gap`: complete and covered, and a hidden event is not impossible there.

*Corollary (an ATTESTATION never observes).* The blindness is not a property of the `gap` partition's name but
of the CLASS: an attestation speaks about documents, an observation about the world. So the predicate is
class-first — no attestation contributes to `Obs`, whatever partitions it carries — and the slot question is
asked only of frames that COVER a slot, which is why a stream checkpoint (covering none) is never asked and
never counted.

*Corollary (naming an instance, again).* The normative text listed one blind case — a `kind:"absence"` with
`reason:"unreachable"` — and the implementation followed the list rather than the rule stated beside it
(“every covered slot was POSITIVELY observed”). A gap record was not on the list, so it passed as observation.
The enumeration must be of the POSITIVE set, which is closed and small, with everything else blind by default:
the same fail-closed shape the `absence` reason vocabulary already uses.

**Binding: realized** — *"F.5v a slot covered ONLY by a signed gap record is BLIND"* · *"F.5v a stream checkpoint inside the window is not asked whether it observed"* · *"noevent-gap-record-is-blind"*.

## F.5w A predicate has a DOMAIN on which it is non-trivial, and key-form is where BINDING is not one (#119, carried up from round 145)

The identity MODES are not two spellings of one thing. §3.1 fixes `key-form ⇒ domain_shard = key_id`, and
`key_id = H("ust:keylog", pub)`, so the name of a key-form publisher IS its key.

**Theorem F.5w (binding is vacuous in key-form).** The impersonation guard on a stream is
`Bound(f) ≡ [ K_A(f.state.id.key_id) = f.sig.pub ]`, where `K_A` is the key set resolved from the authority
named by `domain_shard`. In key-form that authority is `key_id` itself, so `K_A = { key_id ↦ pub }` is the
frame's own key and `Bound(f)` reduces to `pub = pub`. The predicate is therefore an IDENTITY on the key-form
sub-domain: it cannot distinguish any two inputs, and it cannot fail. ∎

*Corollary (a green test drawn only from key-form asserts nothing about binding).* Vacuity here is not weakness
but total absence of discrimination, so a test suite restricted to key-form documents cannot detect the removal
of the guard, its inversion, or its complete absence. MEASURED (#119, 2026-08-02): every hand-written stream
case in the clean-room parity battery was key-form, the clean-room verifier had NO key binding at all, and an
impostor's frames chained onto a VICTIM's genesis were graded a `complete` stream under the victim's name.
The battery was green throughout, and honest — it never asked a question that has an answer.

*Corollary (the general shape, of which this is one instance).* For any verification predicate `P`, let
`dom(P)` be the inputs on which `P` is not constant. A conformance set `S` with `S ∩ dom(P) = ∅` reports the
same verdict whether `P` is implemented, mis-implemented or missing. Coverage must therefore be argued against
`dom(P)`, not against the count of cases: `|S|` is not evidence. The sibling failures of the same day were the
same statement at other layers — a gate that names an INSTANCE of a set, a parity battery that samples a
population — and this one is the sharpest, because here the untested region is defined by a MODE the protocol
itself makes trivially satisfying.

*Corollary (and it is why key-form is `self-asserted`, not merely weak).* A consumer that verifies a key-form
stream and observes that every frame's key is bound has learned NOTHING it did not already hold: it has
confirmed an equality it supplied. This is the same reason F.5a.1 keeps independence consumer-owned — a
property computed from the claimant's own bytes is not evidence about the claimant.

**Binding: realized** — *"F.5w key-form: an impostor is caught by the NAME, never by the binding guard"* · *"F.5w name-form: the SAME impostor keeps the victim name, reaches the binding guard and is refused BY IT"*. The two checks are the theorem made executable: the identical attack is built in both modes and the verdict names WHICH guard answered. Beyond them the realization is the parity gate's population change: the clean-room verifiers are now driven by the CORPUS, whose stream vectors are NAME-form, so `dom(Bound)` is entered by construction rather than by someone remembering to enter it.

## F.5.1 The ladder is REPORTABLE, and each rung names WHICH TERM of R2 its missing input belongs to (#137)

F.5.0 makes assurance a product lattice and the tier one projection. A verdict says where a document sits; it
does not say what stands between the document and the next rung, nor — decisively — **whether that thing is the
publisher's to move at all**.

**The measurement that forces this.** On the reference operator three barriers were crossed in three separate
production deploys, each visible only after the previous was removed: an unearned capacity grant, then an
unconfirmed name, then unproven time. All three were decidable from the SAME bytes and the SAME faculties at the
first deploy. Nothing about the document changed between them; only what the verifier had been asked to attempt.
Reasoning could not even ORDER them — a derivation correct in itself named the second barrier as the first.

**This section introduces no new partition of the inputs.** R2 already fixes it: verification is a total
function of `x̂` and the verifier's OWN faculties `(ℐ_v, ρ_v)`. Every attribution the report can make is a
statement about WHICH of those terms a missing input lives in:

| term | what moves it | who may move it |
|---|---|---|
| `x̂` | author a different document — fewer partitions, a different class, a declared `prev` | the PUBLISHER, and legitimately: the result is a different subject, judged on its own bytes |
| `x̂`'s neighbourhood | publish an artifact the verifier FETCHES and verifies under its own faculties — key log, witness log, anchor | the PUBLISHER emits bytes; what enters the function is the RESULT of the verifier's check, never the publisher's intent |
| `x̂`'s neighbourhood, **attested by another** | no-fork evidence over the active genesis | an INDEPENDENT WITNESS. Not the publisher — an attestation that no rival genesis exists is worth nothing when the attesting party IS the party in question (F.5o). Not the consumer — it cannot manufacture evidence about a publisher it is judging. Collapsing this into the publisher column silently instructs an operator to produce what it is structurally barred from producing |
| `ℐ_v` | bring a trust root, a connector, an accepted issuer | the CONSUMER only |
| `ρ_v` | widen a budget | the CONSUMER only — and R4 admits only a policy that TIGHTENS it |
| **the verifier's RULESET** | implement a newer minor, or a different major | **NEITHER PARTY, in this run.** The document is well-formed and the faculties are whatever they are; what is missing is `v` itself |
| — | nothing: the input is settled absent (F.5p NOT OFFERED) | NOBODY, now or later |

**Corollary F.5.1a (the publisher can never move `(ℐ_v, ρ_v)`, so a report may never advise it to).** This is R4
read in the reporting direction. Telling a publisher that its own verdict would rise if it asserted
`noForkConfirmed` is instructing it to move the consumer's faculties — the self-rooting F.5a.1 excludes, arrived
at through a help message. The two publisher-movable rows above are *author differently* and *publish
something*, and neither is an assertion made TO the verifier. In prose all three read as "the operator can fix
this", which is precisely why the term is named per input rather than inferred by the reader.

**Corollary F.5.1e (a report may name only a term it MEASURED, and a defect in `v` has no row).** The table
assigns every missing input to a term, and F.5.1a fixes who may be advised to move it. Neither settles what a
report may say when it has established nothing. Naming an unmeasured term is not imprecision: the terms differ in
WHO acts, so a wrong term sends the only party who could act away from the problem. And it fails in one
direction. `x̂` and the witness column belong to absent parties; `ℐ_v` and `ρ_v` belong to the reader, who is
present. A report written without measurement drifts to the reader — and the reader's remedy is testable, so the
mis-attribution is confirmed rather than exposed when it does not work.

**A defect in `v` is where this bites, because the table has no row for it.** Every row is a MISSING INPUT. A
verifier that computes the wrong answer over inputs that are all present is not on the table at all, and the
nearest-looking rows are exactly the two aimed at the reader. So an undifferentiated refusal does not merely lose
detail; it converts the one failure no party can act on into an instruction to the one party who cannot fix it.

Hence, where a rung's non-attainment is decided by a CONJUNCTION, **the report names the conjunct that failed and
the values it failed on.** Not as courtesy. A conjunction has one input per conjunct and therefore one term per
conjunct, so an undifferentiated `false` collapses several rows of the table into one word — and F.5.1 is the
statement that those rows are not interchangeable. The operational test is falsifiability: a refusal naming its
conjunct is a claim a reader can check and disprove; a refusal naming the reader's environment is a claim about
the reader, which the reader cannot disprove from where they stand.

The reason set is therefore CLOSED and each element carries its term, under the same equality obligation F.1.1
puts on `K`: a reason outside the set is a verifier defect, and an element never exercised is a claim over an
empty domain. Measured 2026-08-13 on the shipped browser verifier — five distinct failures, three of them
conjuncts of one anchor check, reached the reader as the single word `pending`, annotated *a browser cannot
decide*. The cause was none of the five: the inclusion climb narrowed an index to 32 bits (the corollary in
F.9.5-c.1) and had been wrong for sixteen days. Splitting the conjunction named it in one run. CLOSED 2026-08-13
— round 207 (#155).

**Binding: realized for the witness path** (F.5.1 as a whole stays pending on #137/#138) — *"#155 a witness refusal names its conjunct, and every reason is in the closed set R"* · *"#155 every element of R is exercised, and a reason outside R is refused"*.

**Corollary F.5.1a-bis (a version gap is a rung, and its term is the RULESET).** Let `d` carry minor `m` and let
`V` implement `v < m`. The material `m` adds is not absent from the document and not withheld by any party — it
is present and UNREACHABLE, because `V` has no rules for it. That is a fourth term, and it belongs to neither
side: attributing it to the publisher would advise authoring an older document, and attributing it to the
consumer would advise an upgrade the protocol has no standing to demand.

**So the verdict is neither INVALID nor a plain VALID, and this holds for a MAJOR too.** `INVALID` is a statement
about the BYTES — and it means one thing only: *I applied MY rules and they were violated*. A ruleset the verifier
lacks, a faculty it was not given, a capacity it was not granted are all outside that sentence. A different major
is the extreme case: the verifier has no rules for those bytes at all, so calling them invalid is the same
overclaim as the minor case, one step further out. Minor and major differ in REACH — the additive-only minor
contract still lets `V` evaluate what its own version defines, while a different major leaves it nothing — and not
in validity. Here the bytes are fine — reporting them as broken is F.5t on the time axis, an artifact correct under the protocol
returning the observation reserved for a corrupt one, and it sends the reader to debug the publisher when the
verifier is what is out of date. A plain `VALID` would claim a reach `V` does not have. The honest answer is the
one this section already defines for every other unreached axis: **NOT ATTEMPTED**, naming both `m` and `v`.

**Corollary F.5.1a-ter (why this is not a courtesy).** A verifier that must be current in order to verify
anything is a verifier that stops being run — deployments outlive releases by years, because upgrading a stack
that works is a cost with no local benefit. A protocol whose safety depends on synchronised upgrades across
every consumer has assumed a property of the world it cannot obtain. The refusal is therefore not the strict
choice and the report the lax one; the refusal is the choice that removes verifiers from the field, taking their
verdicts with them. And it lands hardest on CLOSED consumers, which have no discovery surface to learn from and
would see only `INVALID`, forever, with nothing in the answer pointing at their own age.

**This is admissible only because the minor contract is strict.** An older `V` evaluating under older rules must
be RIGHT about what it evaluated, which holds iff a minor only ADDS and never alters the meaning of what an
earlier minor defined — a meaning-change is a MAJOR, where refusal IS correct because a different major is a
different protocol. Without that contract this corollary would license silent wrongness.

**Corollary F.5.1b (the report grants nothing).** The report is a function OF the decision relation, never an
input to it. Adding it leaves every verdict identical — otherwise reading *what would make this HIGH* would
itself be a step toward HIGH. Mechanically: it is derived from the same relation the verdict uses, because a
second implementation is how a report and a verdict drift into disagreeing about the same bytes.

**Corollary F.5.1c (settled and not-brought may not collapse).** A rung unmet because its input is settled
absent and one unmet because an `ℐ_v` input was not brought are different facts for the reader: the first is
finished, the second is a configuration choice they can make. One shape for both discards the distinction F.5p
exists to preserve, on exactly the axis where an integrator decides whether to act at all.

**Corollary F.5.1d (F.5.1b binds in BOTH directions, and the older copy is the VERDICT's).** F.5.1b forbids the
report from becoming a second implementation of the decision relation. The prohibition is symmetric, and when
the report was built the violation already existed on the other side: a verdict `detail` that PRESCRIBES an
input is a remedy relation, evaluated with no reference to the call that produced the verdict.

Let `R(d, o)` be the set of inputs a diagnostic names in a **SUPPLY** remedy for document `d` under options `o` —
a clause promising that providing `i` raises the coordinate. For that promise to be capable of being true, `i`
must be absent from the call, because a run that already HAS `i` has produced the verdict `i` yields. Hence

> **∀ d, o, i ∈ R(d, o). i ∉ dom(o)**

A supply remedy naming a supplied input is not merely unhelpful; it is FALSE, and refuted by the very call that
printed it.

**SUPPLY and REPLACE are different acts, and only the first is bounded by `dom(o)`.** A clause directing the
caller to re-fetch a stale key log, rotate a key, or re-anchor names bytes the call does NOT hold — the input is
present, the ARTEFACT it should carry is not — so the act is outside `R(d, o)` and the invariant does not reach
it. The discriminator is mechanical: a supply remedy's precondition is `i ∉ dom(o)`, which a branch can be made
to establish; a replace remedy's precondition is a property the branch has ALREADY computed as a value (freshness,
revocation, inclusion) and which its condition therefore implies by construction. Conflating the two would delete
the useful half of the diagnostics, and a rule that deletes what works is a rule that gets switched off.

**A literal satisfies this only by accident.** A remedy written as a fixed string inside a verdict branch is
evaluated without reference to `o`. It obeys the constraint exactly when the branch CONDITION implies
`i ∉ dom(o)` — so correctness rests on an unstated coincidence between a guard and a sentence, and drift is
silent because nothing in the tree relates the two. This is the failure F.5.1b names, arrived at from the
opposite end: not a report that reimplements the verdict, but a verdict that reimplements the report.

**The discrimination this makes is the useful half.** `dom(o)` contains INPUTS. A clause advising a different
DOCUMENT — a key-form `domain_shard`, fewer partitions, a declared `prev` — names the `x̂` term of R2 and is not
an element of `R(d, o)` at all, since authoring different bytes is not supplying an input to this call. The
invariant therefore removes exactly the clauses that CAN be false and leaves untouched the ones that cannot.

**Measured, 2026-08-05, on the reference operator, by a consumer holding only the domain name.** A live
`observation` was fetched from the operator's public mirror, its authority resolved from the standard discovery
pair, and the document verified. With `genesis` and `keylog` supplied, `resolveAuthority` returned `ok` and
granted capacity; the ladder correctly moved both inputs from `absent` to `attempted` and named the remaining
barrier as `noForkEvidence`, whose party is an INDEPENDENT WITNESS and which F.5.1 marks movable by neither
side. The verdict detail, on that same call, read `supply genesis to bind the name (→ HIGH)` — byte-identical to
the detail produced when nothing was supplied at all. Its guard is `tier === LIGHT`, which does not imply the
absence its sentence asserts. An operator following it would republish a genesis it had already published,
observe no change, and conclude the protocol was broken — while the input actually blocking it is one the
protocol bars it from producing. **CLOSED 2026-08-05.**

**Realization.** `verify` no longer authors remedies naming a call input. Such clauses are produced by one core
helper given `opts`, which yields nothing when the input it names is present — so a mis-guarded branch degrades
to silence rather than to a promise the call refutes — and `explainLadder` remains the single place that
computes what a call did not supply. Enumerated by `tools/remedy-guard-gate.mjs` over TWO rosters, both read
from source and both required: every verdict `detail` in the core, and every OPTION NAME the core reads.

**The option roster is where this first shipped incomplete, and the failure is the theorem's own shape.** A
name reaches the core by two access forms — `opts.<name>` and DESTRUCTURING — and reading only the first hid
seven options, among them `keylogHeadAnchor`. A supply clause naming that option was already in the tree,
unexamined, while the gate printed PASS; its guard is `freshness === 'unverified'`, which holds equally for an
anchor supplied and not verified. So the gate built to refuse correctness-by-coincidence was itself correct by
coincidence: the two clauses it happened to see use the dotted form. A roster that enumerates one access shape
of two is a sample wearing the word *enumerated*.

**Binding: pending — thelabmd/UST-Protocol#158** — for a CITABLE check, not for the behaviour: the ladder report landed in core at `rev104` and #138’s version vectors run, but no executed check carries this section’s id, so `realized` cannot honestly be written here. #137 and #138 closed on 2026-08-06 and 2026-08-04; this line named them for a week afterwards (#156).

**Conformance (math ⇒ code ⇒ green vector, once realized).**
- the report is derived from the SAME decision relation as the verdict; no second implementation.
- no rung attributes an `ℐ_v`/`ρ_v` input to the publisher.
- a rung whose input is settled is reported distinguishably from one whose input was merely not brought.
- **a rung decided by a conjunction reports WHICH conjunct failed, from a closed reason set (F.5.1e).** The
  refusal must be falsifiable by the reader; naming the reader's own environment is not.
- **no verdict detail names a remedy the call already supplied (F.5.1d).** The vector pair is the theorem: the
  same document verified with and without an input must not produce the same prescriptive clause naming it.

**Corollary F.5.1f (a refusal carries every MEASURED fact and no DISPOSITIVE field).** The report corollaries
above govern what a diagnostic may say. This one governs what the REFUSAL ITSELF carries, which is a different
surface and was starved by an argument that reads as prudence.

Let `A(d, ℐ)` be the assurance state and `C(d)` the claim the document makes by its own form — a name-form
`domain_shard` claims a name, a key-form claims only a key. The disposition is `VALID:π(A)` when `A` decides `C`
and `INDETERMINATE` when it does not. A refusal is therefore not the statement that `A` is unknown; it is the
statement that `A` does not reach `C`. Withholding a coordinate of `A` that WAS measured returns strictly less
than the run established, on precisely the branch where the reader must decide what to bring, and the
measurement is already spent.

**§14 had already settled both halves, and the verdict did not carry them.** The normative text states that
`INDETERMINATE` carries NO tier and that *its assurance is PARTIAL, not `⊥`* — this corollary derives the same
two facts from R2 rather than introducing them, which is the honest record: the rule existed and nothing
returned it. That makes the defect the same class as F.5p's — an obligation stated where no surface discharges
it — and not a gap in the rules.

**The lattice has no value meaning NOT EVALUATED, and the first attempt at this corollary assumed it did.**
The tempting argument is that `A` is total — every axis is a chain with a floor, so an unfinished run reports
`⊥` rather than an absence. Measured against the axes, that argument is false on one coordinate, and the
asymmetry is why §14 says PARTIAL rather than `⊥`:

| axis | floor | what the floor SAYS |
|---|---|---|
| identity | `self-asserted` | nothing beyond the document's own key was established |
| freshness | `unverified` | nothing about currency was established |
| time | `unproven` | no anchor was established |
| **integrity** | **`invalid`** | **the canon/hash/signature check RAN and FAILED** |

Three floors mean *nothing proven*; the fourth is a FINDING. So `⊥` is not the honest report of an unfinished
run — a refusal emitting it would assert the document is invalid, which is the one thing §14 forbids a refusal
to say (*inability is not guilt*). Hence a coordinate of `A` rides the refusal exactly when it was MEASURED, and
an unmeasured coordinate is ABSENT — absence being the word this tree already uses where a slot has no honest
value. A refusal reporting `integrity: invalid` is an INVALID verdict wearing an INDETERMINATE label, and a gate
must refuse it.

**The projection may not ride, and the reason is NOT informational.** `π` is a function of `A`, so a refusal
carrying `A` already determines the tier: withholding the field withholds no INFORMATION, and any argument
phrased that way is false. The prohibition is about AFFORDANCE. Let `F` be the fields on which a consumer
branches in order to PROCEED — `result` and the tier. §14/#44 makes a refusal un-skippable by returning it as an
error the caller must acknowledge rather than a datum it may read past; a refusal object carrying the tier is
SHAPED like an answer, and the shape is what licenses the act. Hence

> a refusal carries every coordinate of `A` and no member of `F`.

The information stays reachable — `π` (`projectTier`) is exported and normative — so a consumer that wants the
projection computes it in its own code. That is a different act from reading a field, and the difference is the
whole of the protection: we do not hide the tier, we decline to pre-chew it.

**Attribution belongs on a refusal a fortiori, and the standing argument for excluding it is unsound.** The
attribution rule was stated as *every VALID verdict carries both fields; a refusal carries neither (nothing to
attribute)*. Consider a refusal whose cause is an ABSENT FACULTY — `INDETERMINATE(unsupported_alg)`, the case
§14 already normalizes. Its entire content is a fact about the VERIFIER: this build cannot evaluate the
primitive, and a build that can answers normally on the same bytes. Attribution is then the only coordinate that
separates *the document does not support the claim* from *this build could not evaluate it*, which are opposite
instructions to the reader. And `verifier`/`registry_digest` are not members of `F`: nobody proceeds on a
version. So the exclusion removed a fact exactly where it decides the reader's next move.

**Realization (rc.72 line, REV 70).** One refusal shape across the core verdict, the MCP tool result and the
operator feed's FULL projection: `assurance` (the measured axes), `absent` (the same array `explainLadder`
computes, each entry naming its `party` and whether it is `movable`), `verifier` and `registry_digest`. No
`tier`. A gate holds BOTH halves — every measured fact present on the refusal, and no dispositive field present
— because a one-directional check would be satisfied by a refusal that simply became an answer.

**Conformance.**
- `A` is returned where it was measured: *"F.5.1f a refusal carries the MEASURED assurance axes"*.
- and never invented where it was not: *"F.5.1f a refusal never reports integrity invalid — the one floor that is a finding"*.
- the dispositive field never rides: *"F.5.1f a refusal carries NO tier — the field a consumer branches on to proceed"*.
- attribution on a refusal: *"F.5.1f a refusal names the vocabulary that refused (verifier + registry_digest)"*.
- one computation, not two (F.5.1b): *"F.5.1f the refusal's absent[] is what explainLadder computes, not a second derivation"*.

## F.5x Authorization reads the DOCUMENT, so `class` is not one axis among several — it is the only one there is (#130)

Round 149 stated the class-sets for `admits(k, c)` and an operator immediately asked the reasonable question:
should a role bound the CLASS a key may sign, or the TIER whose chain it may extend? The question dissolves,
and the dissolution is worth writing down because the same shape will be asked again of every future
refinement.

**Setting.** A State's identity coordinates are exactly `domain_shard, ust_id, key_id, class, parent_ust`
(§4.2, and any other key at that level is `E-MALFORMED`). Authority is resolved from `domain_shard`: it names
the genesis, the genesis fixes the key set, the key set admits the signature.

**Theorem F.5x.1 (a per-document predicate ranges only over document coordinates).** `admits` is evaluated
where authority is decided — at a single document, before any sequence is known. Its arguments must therefore
be readable from that document. `tier` is not: §11.3 defines a stream as `(domain_shard, tier)` and the tier is
recoverable only by WALKING `prev` to the stream it belongs to. So `admits(k, tier)` is not a stronger axis
than `admits(k, c)`; it is not evaluable at that layer at all. Of the coordinates a document does carry, only
`class` describes what the document IS. ∎

*Corollary (this was never a choice).* Choosing "class or tier" reads like a design fork and is not one. Any
axis a document does not carry can only be enforced where sequences are verified, and that enforcement already
exists and is a different mechanism: `verifyStream` binds every frame's key to the resolved authority set. A
role does not compete with it and cannot replace it.

**Theorem F.5x.2 (two services under ONE authority are not separable by role when they share a class).** Let
services `A` and `B` publish under the same `domain_shard` and both emit documents of class `c`. Their
signatures are then admitted by the same predicate `admits(·, c)`, so no assignment of roles distinguishes
them: a role that admits `c` for one admits `c` for the other. Separation of what a key may AUTHORIZE
therefore requires separation of `domain_shard` — the coordinate that resolves to a key set. ∎

*Corollary (the operator instance).* A liveness observer emits `class:"observation"` — it saw the silence
itself — and so does the publisher's slot stream. Under one name, no role separates them; the observer's key
is a publisher key. Under its own name, the containment is not a field a reader must consult but the identity
resolution itself.

**Theorem F.5x.3 (a second name cannot manufacture apparent independence, so containment and self-deception
are not a trade-off).** The objection to a second name is that one operator holding two names LOOKS plural.
But independence is not in `σ(bytes)` (F.5o): a verifier cannot derive it from names, and must take it from
its own trust roots. MEASURED on the reference operator (2026-08-02): resolving its own served witness yields

    no independent no-fork evidence; a served witness only corroborates → authority pending

`corroborated`, never `authoritative`. The protocol REFUSES to read two names of one operator as
independence; a correct consumer therefore cannot be misled by the structure. ∎

*Corollary (where the deception can actually live).* Not in the key layout — in the PROSE. An operator may
still cite its own secondary as if it were third-party evidence, and no verifier is consulted when a human
reads a claim. So the discipline this needs is one of CITATION, and it is the operator's, not the protocol's.

**Binding: realized** — *"admits-issuance-observation-refused"* · *"F.5v a stream checkpoint inside the window is not asked whether it observed"*. F.5x.1 is realized by the shape of the predicate that shipped in round 149 (it takes a class because a document offers nothing else); F.5x.3 by the measured refusal above, which is the same path `#113` tracks.

## F.5y A re-rooting is a CROSSING of every genesis-rooted structure the publisher instantiated, not an event (#131)

Round 152 set out to build the missing re-rooting command and began, reasonably, by asking the code which key
signs a re-rooting. The code answered — epoch A's authority checkpoint key — and the answer was wrong by omission.
It names the key of ONE mechanism and stops. The correct answer is not a key but a domain, and the shape of the
mistake is the reason this section exists.

**Setting.** Let `g_A` be the active name-binding genesis for domain `n`, let `g_B` succeed it, and write
`ρ(·) = contentHash(·)`. Several structures a publisher maintains are ROOTED in `ρ(g_A)` — their first element,
or their active pointer, names it:

| structure | binding to the genesis | refusal when the binding is stale |
|---|---|---|
| key-log | entry 0 `prev = ρ(g)` | `E-PREV` |
| cadence log | entry 0 `prev = ρ(g)` | `E-PREV` |
| witness log | `active = ρ(g)` | `fork` |
| authority-checkpoint chain | `C₀.active_genesis = ρ(g)`, `genesis_epoch = H(ρ(g))` | `E-MALFORMED` (no valid `τ`) |
| the frame stream | frame 0 `prev = ρ(g)` (M4) | `E-PREV` |

Call this set `R(g)`. Its members are not a list chosen here; each is a place where a verifier already reads
`ρ(genesis)` and compares.

*Boundary case, recorded because it was mis-classified once.* A field may be genesis-rooted in the WRITER and
still not be a member, when no verifier reads it. A stream checkpoint's `prev` chains from the genesis for the
first entry of that chain (§9), which has the shape of a sixth member — and is not one. MEASURED: a stream
checkpoint whose chain roots in `g_A` yields `complete` under `g_B`, and no verifier reads that `prev` at all;
only its PRESENCE is required (§11.3). By F.5y.1's own standard — independence by EXHIBITION, which demands a
configuration where the verifier REFUSES — a field with no refusal cannot be exhibited and is therefore not an
axis. Whether that field SHOULD be verified is a separate question of the F.7c kind, tracked as
UST-Protocol#134; until it is answered, the domain is five.

**Theorem F.5y.1 (the crossings are INDEPENDENT, by exhibition).** For each `S ∈ R(g_A)` there is a
configuration in which every other member is correctly re-rooted onto `g_B`, `S` alone is not, and the verifier
REFUSES. Hence no crossing is implied by any other, and a re-rooting that performs `k < |R|` of them is
incomplete no matter which `k`. The exhibits are the vectors: *"F.5y an uncrossed cadence log is REFUSED under
the successor genesis"*, *"F.5y an uncrossed witness log makes the publisher its OWN fork"*, *"F.5y an
uncrossed frame stream is REFUSED under the successor genesis (M4)"*. ∎

The witness exhibit deserves its own sentence, because the intuitive statement of it is too weak. Leaving the
witness log on `g_A` while serving `g_B` does not merely strand a consumer holding the old hash: §12.1's rule —
an anchored active entry that DIFFERS from the resolved genesis is a rival — does not care that both roots
belong to the same operator. The publisher becomes its own fork, and the ANCHORED root is the superseded one.

**Theorem F.5y.2 (the obligation ranges over the INSTANTIATED set).** `S ∈ R(g_A)` imposes a crossing only if
`S` is instantiated, and the reason is structural rather than pragmatic: each refusal above is conditioned on
`S` being READABLE. An absent witness endpoint yields `unreachable`, not `fork`; where no authority checkpoint
was ever published there is no prior `genesis_epoch` to reset, so no `τ` is owed. The obligation is therefore
`R(g_A) ∩ Instantiated`, and instantiation is OBSERVABLE at the serving surface — a served log, a declared
`checkpoint_authority`, a running writer. ∎

*Corollary (why a tool must READ and never ask).* The obligation is a function of the served state, so a
command taking the axes as flags asks the operator to restate what the system already knows — and an omitted
flag is then indistinguishable from an absent structure, which is the difference between “nothing to cross”
and “forgot to cross”. The correct shape is the one `ust key add --role` already has: what is REQUIRED is a
property of the served genesis, not of the command.

**Theorem F.5y.3 (an uncrossed axis is invisible to the ceremony and loud at the consumer).** Every refusal in
`R` is produced by a VERIFIER, from inputs the ceremony does not hold. A ceremony's self-check ranges over what
the ceremony PRODUCED; an uncrossed `S` is precisely a structure the ceremony did not touch, so no check over
its own outputs can observe it. Acceptance must therefore be indexed by the PRE-state — the structures observed
instantiated before the crossing — and never by the artifact set produced. ∎

*Corollary (the operator instance, and the worst member of `R`).* The frame stream is instantiated by a RUNNING
WRITER rather than by a served document, so its crossing is a change in production code: the first frame after
the boundary must set `prev = ρ(g_B)`. A writer that continues its chain across the boundary is refused
`E-PREV` for every consumer holding `g_B` while the ceremony reports success — the failure is in production, and
visible only at the consumer. Old epochs are unaffected throughout: each epoch's stream is its own chain rooted
in its own genesis, which is the design and not a casualty.

**Method note (kept because the near-miss generalizes).** A rule stated over a SAMPLE — “the two mechanisms” —
would have licensed a command that silently omits three axes, with green acceptance. Three of the five were
found only by enumerating from the verifier's own reads instead of from the mechanism names, which is the same
discipline a gate owes its domain: enumerate, never sample.

**Binding: realized** — *"F.5y an uncrossed cadence log is REFUSED under the successor genesis"* · *"F.5y an uncrossed frame stream is REFUSED under the successor genesis (M4)"* · *"F.5y an uncrossed witness log makes the publisher its OWN fork"* · *"F.5y the crossing preserves the superseded root and its anchors"*. Until 2026-08-13 this line read `pending — #131 (the crossing command … the composite ceremony is not)`; #131 shipped that ceremony and closed on 2026-08-03, and the sentence denying it went on running in CI beside the four checks that contradict it for ten days (#156).

## F.5z A supersession is a TERMINAL KEY-LOG ACT — the carrier is forced, not chosen (#133)

§12.1 P2 makes a supersession authoritative iff BOTH (a) it is signed by the old genesis key AND (b) it is
reflected in the current name-binding root. (b) has a wire form — the served genesis, indexed by the witness log.
(a) has none: supersession is expressed only as an unsigned `superseded_by` field, and measured across the
reference implementation and the browser verifier, nothing emits or checks a signature for it.

That the requirement is real was itself contested and settled by measurement. A domain takeover — a lapsed
registration, a compromised registrar, a sold name — produces a well-formed `confirmed` supersession with ZERO
signatures from the outgoing publisher: `witnessSuccessor` builds it, `witnessNoShrink` passes it, and
`witnessNoFork` never applies the no-shrink rule at read time, so a consumer with no cached copy has nothing to
compare against. The two conjuncts answer different questions — (b) *who serves this name now*, (a) *is this the
same identity continuing, or a different one that acquired the name* — and the objection that a LOST root key
would strand a name dissolves: what is lost is the ability to claim CONTINUITY, not the ability to publish. A
fresh genesis under a familiar name reads as a new identity, which for a re-registered domain is the honest
answer §12.1 P3 asks for.

**Theorem F.5z.1 (the epoch transition cannot carry (a)).** The transition `τ` (F.5m) binds `to_active_genesis`
and is signed by epoch A's authority checkpoint key. Three separate reasons disqualify it. Its signer is a
genesis-NAMED delegate, so a `τ`-only hand-over falls to compromise of the delegate alone — strictly weaker than
the guarantee §12.1 P2 names. By F.5y the axes are independent, and `τ` is the AUTHORITY crossing: it asserts that
the authority process continues into `g_B`, never that the name-binding root is succeeded by it. And `τ` does not
exist at all for a publisher that declares no authority checkpoint key, so it cannot be the general form. ∎

**Theorem F.5z.2 (the carrier is DETERMINED).** The statement is signed by the root, and under a DECLARED regime
the root admits exactly `{genesis, key, cadence}` (F.5e.1, rev91). Eliminate:

- `genesis` — a genesis-class document IS the self-signed name-binding root (`key_id = sig.key_id`, `pub` in its
  own value). A second document of that class naming a DIFFERENT root makes the class mean two things, and a
  verifier resolving a name would have to decide which one it is looking at. Refused by the same discipline that
  qualified two earlier collision-words after each was found to span two mechanisms.
- `cadence` — its object is the grid and it is chained in its own log; it has no relation to the name.
- `key` — the key log is the ROOT's authenticated act stream. It is already root-only (rev97), already chained
  from the genesis, and already fetched by any consumer that resolved the old genesis.

One admissible carrier remains, so the shape is forced rather than preferred — and by F.7c a forced answer is the
only kind this layer accepts. ∎

*Corollary (discoverability stops being a separate problem).* ~~A consumer holding `contentHash(g_A)` resolves
authority by fetching that genesis and its key log. The supersession therefore arrives on a surface it ALREADY
reads: no new well-known path, no second fetch, and the stranded-consumer failure disappears without anyone
inventing a discovery mechanism for it.~~ **WRONG, and corrected in place rather than rewritten (rev100).**
§20.1 defines exactly ONE key-log path, and after a re-rooting it serves the NEW epoch's log. Measured: a
consumer holding `hA` fetches it, receives a log chaining from `g_B`, and is refused `E-PREV` — the signed half
is unreachable at precisely the moment it is needed. The reasoning was right that the key log is the CARRIER and
wrong that carriage implies DELIVERY. F.5z.4 and F.5z.5 replace it; F.5z.1–F.5z.3 are untouched.

**Theorem F.5z.4 (delivery is not the protocol's to guarantee, and the consumer's default is already correct).**
No served endpoint can distinguish ABSENCE from WITHHOLDING: the publisher chooses what it serves, so for any
path `p`, "no supersession exists" and "the supersession is not being handed to you" are the same observation.
Therefore no choice of path makes delivery guaranteed, and a design that tries buys nothing. What must hold
instead is that the consumer's behaviour WITHOUT the proof is safe — and §12.1 P2 already provides it: a
supersession missing either conjunct is IGNORED. A consumer holding `hA` that finds `g_B` served and no signed
supersession therefore does not follow; it observes a name serving a root that is not its own, which is a
REFUSAL, not a stranding. Delivery is consequently an incentive on the publisher — be followed — and never an
obligation the protocol can enforce. ∎

*Corollary (the earlier framing inverted the burden).* The replaced text treated a consumer that cannot reach
the proof as a victim of a missing mechanism. It is instead a consumer behaving correctly: continuity is a claim,
an unreachable claim is an unproven one, and unproven claims are refused everywhere else in this protocol.

**Theorem F.5z.5 (the courier is the witness log, and it remains an index).** By F.5z.4 the only open question is
where a publisher that WANTS its continuity recognized should place the transcript so a consumer finds it without
a new mechanism. The witness log already (i) is fetched when resolving name authority, (ii) is keyed per genesis
by `content_hash`, and (iii) carries the UNSIGNED half — `superseded_by` — on exactly the entry that needs the
signed one. Placing the transcript on that entry grants the endpoint no authority: the transcript verifies against
`g_A`'s own root key, which the consumer holds by hypothesis, so the log can OMIT but never FORGE — the same
standing an anchor proof has there. No other served surface has all three properties, so the courier is forced
in the same way the carrier was. ∎

*Corollary (the two halves must agree).* An entry whose `superseded_by` differs from its transcript's
`to_genesis` is contradictory and fails closed — the same discipline that already refuses a `content_hash`
listed both active and superseded.

*Corollary (the log is under the genesis, and that is no objection).* Being “under” the genesis describes what
AUTHORIZES the log, not what it may speak about. The root is the party being superseded and the only one entitled
to say so; its own act stream is where it says things.

**Theorem F.5z.3 (the act is TERMINAL).** Let the operation be `reroot(to_genesis)`. After it the log admits no
further entry: the root has named its successor, so any later act is authority exercised after its own hand-over —
the same equivocation `superseded_by` prevents on the name axis. Terminality is decidable locally (a `reroot` may
only be the last entry of the log), which makes the log's own head the proof that the epoch ended, with no
external evidence required. ∎

**Naming, before the ambiguity does damage.** `supersedes` ALREADY names key-to-key succession inside a key-log
entry (F.5e.2). Calling this operation `supersede` would be the fourth time in this project that one word spanned
two mechanisms, and the previous three each caused a wrong edit before anyone noticed. The operation is `reroot`
and its field is `to_genesis`.

**Binding: realized** — *"F.5z a root-signed `reroot` resolves and REPORTS the successor"* · *"F.5z the key log is TERMINAL after a `reroot` — a later entry is refused"* · *"F.5z a `reroot` naming its OWN genesis is a cycle, not a supersession"* · *"F.5z the `reroot` field set is CLOSED — a stray field is refused"* · *"F.5z.4 a supersession claimed with NO signed half is refused, not followed"* · *"F.5z.5 the two halves must AGREE — an index naming a different successor fails closed"* · *"F.5z.5 no-shrink refuses a log that DROPPED the signed half"*. Until 2026-08-13 this line read `pending — #133 (the operation is specified here and not yet realized, and the requirement it serves has no wire form at all)` — while thirteen `F.5z` checks ran on every build. #133 closed 2026-08-03; the denial stood for ten days, which is the decay #156 is about: a deferral is the one binding form whose truth changes with nobody editing anything.

## F.6 Composition — the event algebra

An **anchored existence-and-commitment claim** is an event `A ∈ Fₜ`; an UNANCHORED signed claim is a document
predicate and enters `Fₜ` only upon anchoring (a LIGHT document's statements exist before any journal sees
them). Because each `Fₜ` is a σ-algebra, anchored claims are closed under `∩` (AND), `∪` (OR), and `ᶜ` (NOT).
The §9 combinators are exactly this closure:

- **Attestation** over constituents `c₁,…,cₙ` commits to the conjunction `A = A₁ ∩ … ∩ Aₙ` where each `Aᵢ` is
  the EXISTENCE-and-commitment event of record `i` — never its truth, and (per §14a) the attestation alone does
  not even verify the constituents' own signatures; it fixes the SET. The Merkle `root` is the binding of that
  set; walking into the constituents is the referent walk (depth-budgeted, reported).
- **Derivation** has TWO strengths that must not be conflated. `based_on` alone is a **declared** lineage —
  `DeclaredDerivation(d, H)`, the publisher's signed CLAIM that `d` draws on hashes `H`; it does not prove any
  particular function was applied. Only when a verifier holds a deterministic profile `φ`, the source documents,
  and recomputes — `VerifiedDerivation_φ(d, H)` — is `d = φ(H)` measurable, and only THEN does composition of
  measurable maps propagate provenance measurability along the DAG (`E-CYCLE`
  guarantees `φ` is well-founded / acyclic).

So "combine" never manufactures information — it only takes measurable functions of already-measurable events.

**Realization (rev85 — domain totality).** composition is an algebra over constituents, not a free-form merge: an attestation whose root does not equal its constituents is refused — *"#44 E-ROOT → obligation §9.4 attestation-root + expected/actual"*

## F.7 The certainty predicate — and where probability is (and isn't) load-bearing

For a committed record with event `A ∈ Fₜ`, no probability measure is needed to state the certainty claim —
it is a MEASURABILITY statement (formally: under ANY measure, e.g. a point mass on the realized history,
`E[1_A | Fₜ] = 1_A`; we do not rely on one):

  **1_A is Fₜ-measurable, and on the event `A` itself `1_A = 1` — i.e. `1_A(ω*) = 1` for a realized history `ω*`
  whose inclusion proof checks (not globally on Ω, where histories without the commitment give `1_A = 0`).**

That is the precise content of the informal `P(record(ω,t) | Fₜ) = 1`: *given the filtration at `t`, whether the record was
committed is already known* (measurable) and, for a valid sealed record, certain. **In pure UST every verdict is
deterministic — `0/1` — so the probability is degenerate.** The genuinely load-bearing structure is the
**filtered measurable space `(Ω, F, {Fₜ})` plus a deterministic measurability predicate**, not a probability
measure. Rigor demands saying so plainly: UST has no randomness of its own.

Probability becomes non-degenerate at **exactly one boundary** — the measurement gap of §F.2. Modelling
the deviation `ε` (with `M = m(Y, ε)`, §F.2 — no subtraction exists on strings) as a random variable is where a
real (non-`0/1`) measure lives. UST deliberately does **not** model it:
it fixes `M` (with `ε` baked in) and stops. So the honest scoping is:

- **filtration ⇒ verification** (deterministic, the heart of UST);
- **probability ⇒ measurement error only** (downstream of UST, in whatever application reasons about how far a
  publisher's measurement `M` might deviate from the truth `Y`).

Conflating the two — reading `P(...) = 1` as if UST asserted something probabilistic about *reality* — is the
formal shape of the "signed = true" over-read the whole protocol exists to forbid.

**Binding: none — definitional.** The certainty predicate names when a record is certain GIVEN the filtration; its operational content is the tier projection, realized in F.5.0.

## F.7a Scope note — private layers

Private partitions and layer chains (§10/§10a) are REPRESENTED here only through their commitments: a blinded
or encrypted layer contributes its commitment event to `Fₜ` exactly like a public one (existence and time are
public facts), while its VALUE remains outside every `ℐ` that lacks the disclosure. Selective disclosure is,
in this language, a controlled enlargement of a particular consumer's `ℐ` — the σ-algebras of §F.5 do not
change; what changes is who holds which generators. A fuller treatment of multi-party layer graphs (who can
prove membership of which layer to whom) is future work and NOT claimed by this appendix.

**Binding: none — definitional.** A scope note delimiting the private layers; it states no property of the verifier.

## F.7b Ω, concretely (instantiation note)

Ω is the space of complete world-histories: each ω is one full assignment of timestamped events — physical
readings, computations, publications. The model needs only a MEASURABLE space (σ-algebras of information),
never a probability measure (F.7): the realized history is a single ω, and the filtration `F_t` is generated
by the anchor journal — a PARTIAL observation of ω up to `t`. UST records fix the publisher's MEASUREMENT `M`
of coordinates of ω, never the true `Y` (F.2). Implementations never instantiate Ω in code; it exists so that
"verification is a measurability test" is precise. Two conforming verifiers agree not because they share an
interpretation of Ω but because they evaluate the same TOTAL function of the same record (I4) — Ω-independence
is the point, not a gap.

**Binding: none — definitional.** An instantiation note showing one concrete reading of Ω; illustrative, not obligating.

## F.7c A normative statement is DETERMINED, or it is unfinished — a preference is not an answer

A protocol earns its name by giving two independent parties the same answer. So a place in the normative
surface where the answer depends on WHO IS ASKED is not a liberty granted to implementers; it is a rule that
has not been found yet.

**The distinction that keeps this from proving too much.** Two different things look like a choice:

- a **parameter** — cadence, capacity, the anchoring window, a consumer's trust roots. The protocol EXPECTS the
  value to differ, the value is DECLARED, and the verdict is a function of the declaration. Two operators
  choosing differently are both answered correctly, and each answer is reproducible by anyone holding the same
  declaration;
- an **undetermined rule** — what a field MEANS, which classes a role admits, whether an absence is a gap. Here
  two answers give two different verdicts **on the same bytes under the same consumer configuration**, so the
  meaning is not fixed and conformance is unstated.

**The test is therefore mechanical.** Hold the bytes and the consumer configuration fixed and vary only the
disputed answer. If the verdict moves, the dispute is about a RULE and must be resolved before the text ships.
If the verdict follows a declaration instead, it is a parameter and the freedom is designed.

**Corollary (a vocabulary must answer for every member).** §12.2 closes the key-role vocabulary with an explicit
reason: the role is read by a CONSUMER, so an open field would make “what did this signature mean” a question
addressed to the publisher rather than to the protocol. A CLOSED vocabulary that leaves one member without a
stated meaning has the identical defect for that member — the question is unanswerable by the protocol exactly
where it was supposed to be answered. Closing a vocabulary and leaving a hole in it are the same omission.

**Corollary (where the freedom actually lives).** An operator's genuine liberty is the DECLARATION: whether to
declare role separation at all, what cadence to run, what to anchor and how often. Inside a declaration the
consequences are determined. That is why declaring is cheap to reason about and expensive to change — and why
`optional` at ceremony time is never a neutral default but a permanent decision taken by omission.

**Binding: none — definitional.** It states a discipline for normative text, not a property of a document, so no artifact verifies or falsifies it; the obligation it creates is on the text's authors and is discharged by the sections that resolve rather than defer.

## F.8 What this model does NOT claim

- It does not claim `M = Y` (truth); only that `M` is fixed and attributable (§F.2).
- It does not add a probability measure to `Ω`; the core is deterministic (§F.7).
- It does not change any normative rule; if it reads as stronger or weaker than `UST-1.0.md`, the normative text
  governs (§F.1).
- The σ-algebras of §F.5 are a *semantics* of the existing checks, not a new verification procedure — a conforming
  verifier is still defined by §14, not by this appendix.
- This appendix is a RIGOROUS-INFORMAL semantics: definitions and proof sketches at working-mathematician
  precision, not a machine-checked or journal-refereed development. An independent professional measure-theory
  review is an OPEN assurance gate (it pairs with the pending human cryptographic audit); until it lands, cite
  this appendix as the protocol's semantics, not as a peer-reviewed theorem set.

**Binding: none — definitional.** It enumerates what the model does NOT claim. A negative scope statement has no realization by construction.

## F.9 Resource-bounded verification (non-normative; the numbers stay normative in §13)

Information is not the only condition of decidability: a verifier also operates under a finite resource
budget. Alongside its information set `ℐ_v`, give every verifier a budget `ρ_v = (M_v, T_v, S_v, N_v)` —
memory, time, safe stack depth, and the provenance-node allowance. A verifier lives in the PAIR `(ℐ_v, ρ_v)`.
For a transcript `R` define the size vector

  `μ(R) = (B, P, D, A, F, W, K)`

— canonical UTF-8 bytes of the signed content, partition count, nesting depth, max array length, direct
reference breadth, per-call walk volume, and the examined key-log epoch length. Let
`C_v : DocSpace × Request → ℝ⁴₊` be the resource-cost vector of parsing, canonicalising, hashing, signature
verification and the requested walk — components `(memory bytes, time, stack frames, visited nodes)` for
verifier `v`'s implementation — with `ρ_v ∈ ℝ⁴₊` and `⪯` the COMPONENTWISE partial order (`a ⪯ b ⇔ aᵢ ≤ bᵢ`
for all four); "insufficient resources" means SOME component exceeds its budget. A tier predicate is decidable
by `v` only when BOTH hold: `𝒮_τ ⊆ ℐ_v` (information) and `C_v(R) ⪯ ρ_v` (computation). Missing information
yields `INDETERMINATE(unavailable)`; insufficient local resources yield `INDETERMINATE(resource_limit)`
(the wire reasons of §15). Neither makes a protocol-valid transcript INVALID.

**Binding: none — numbers-normative-in-§13.** The section says so itself: the numbers stay normative in §13, and the bounds checks realize them there.

### F.9.1 Extensive and structural metrics

A metric is a **VOLUME** metric when legitimate publisher data increases it extensively (≈ additively under
union), growth leaves the verification CONTROL STRUCTURE unchanged (more of the same work, not different
work), and excess payload admits a commitment-preserving externalization (content-address the bulk, keep the
signed hash). `B` and `P` are VOLUME metrics; per-partition ciphertext bytes are volume too but NOT an
independent coordinate of `μ_V` — they are already included in `B(R)`, and any separate per-partition ciphertext
cap is an admission rule outside `κ` (classification and vector stay aligned, 18th round). A metric is a **STRUCTURE**
metric when increasing it enlarges recursion, branching, traversal or resolution state for EVERY verifier
regardless of publisher authority, and a protocol-native transformation can express the same data without the
increase. `D, A, F, W, K` are STRUCTURE metrics. Hence the law:

  **Authority may enlarge legitimate volume, but cannot make structure cheaper to verify.**

That is why VOLUME bounds are ceremony-declarable and STRUCTURE bounds are protocol-wide laws (§13).

**Binding: none — numbers-normative-in-§13.** Metric definitions feeding §13; the obligations are the §13 bounds.

### F.9.2 Capacity earned by authority

Let `κ₀ = (B₀, P₀)` be the universal LIGHT floor, `κ_ABS = (B_ABS, P_ABS)` the protocol ceiling, and let an
authoritative genesis declare `κ_G` subject to `κ₀ ⪯ κ_G ⪯ κ_ABS` (an out-of-range declaration is not a valid
declaration — the floor applies). The declaration is EFFECTIVE only when its genesis binding lies in the
verifier's authority information: `G_κ ∈ 𝒜` and `𝒜 ⊆ ℐ_v`. Effective capacity:

  `κ(R, ℐ_v) = κ_G` if the authoritative genesis is verified and in range; `κ₀` otherwise.

A self-signed declaration does not enlarge capacity because key possession alone never places it in the
name-authority σ-algebra: `𝒜 ⊄ ℒ`. On the wire this is rc.12's TRUSTED GRANT: the grant flows FROM
`resolveAuthority` (or the caller's pin/policy), never from a caller-attached genesis document.

**Binding: none — numbers-normative-in-§13.** Capacity is a reading of the §13 constants, not an independent obligation.

### F.9.3 Bounded-verification verdict

With `S_ABS` the vector of absolute STRUCTURE bounds:

  `V(R; ℐ_v, ρ_v) =`
  `INVALID(E-BOUNDS)` if `μ_S(R) ⋠ S_ABS` — structure over the absolute law;
  `INVALID(E-BOUNDS)` if `μ_V(R) ⋠ κ_ABS` — volume over the absolute protocol ceiling (checked BEFORE authority:
    a 1 GiB transcript is not-a-UST regardless of any grant — the reference impl already tests `sBytes > ABS`
    first, rc.12; the model now matches it);
  `INDETERMINATE(unavailable)` if `μ_V(R) ⋠ κ₀ ∧ μ_V(R) ⪯ κ_ABS` and no trusted grant is in `ℐ_v` — evidence missing;
  `INVALID(E-BOUNDS)` if `μ_V(R) ⋠ κ(R, ℐ_v)` — over the granted capacity;
  `INDETERMINATE(resource_limit)` if `C_v(R) ⋠ ρ_v` — beyond THIS verifier;
  `Valid_τ(R)` otherwise.

Protocol invalidity (structure OR absolute volume), missing authority evidence and insufficient verifier
resources are distinct states.
Transport admission (refusing an over-budget RAW input before decoding) is a fourth, pre-verdict state: a
refusal to start, reported as `resource_limit`, never a statement about the document.

**Binding: none — numbers-normative-in-§13.** The bounded verdict shape is normative in §13 and realized by its bounds checks.

### F.9.4 Portability of the LIGHT floor

Let `𝓔₀` be the declared class of baseline environments and `ρ₀ = inf_{e∈𝓔₀} ρ_e`. The floor is PORTABLE
exactly when **every environment meets ITS OWN budget**: `∀ e ∈ 𝓔₀ : sup { C_e(R) : μ_V(R) ⪯ κ₀, μ_S(R) ⪯ S_ABS }
⪯ ρ_e` (the crossed form `sup_e C_e ⪯ inf_e ρ_e` is sufficient but NOT necessary — a heavy-but-well-budgeted
environment and a light-but-tight one can each pass their own condition while failing the crossed one — 18th-round fix) — every transcript inside the floor is both
information-decidable from its own bytes and computationally decidable by every baseline implementation. This
is the resource form of LIGHT self-containment.

**Binding: none — numbers-normative-in-§13.** Portability of the LIGHT floor is a consequence of the §13 numbers.

### F.9.5 Structural escape transformations

An absolute STRUCTURE bound does not reduce expressive power when a protocol-native, commitment-preserving
transformation exists: `4096 = 64²` (a two-level attestation tree carries the full constituent universe at
breadth 64); oversized arrays chunk; deep data restructures; long key histories split into re-genesis epochs;
long walks continue across bounded calls. Each transformation preserves the existence and hash-binding of the
represented state while keeping every single verification inside a universal resource envelope.

**The escape is checked against what the protocol can ADDRESS, not merely asserted as sufficient (rev65).**
`4096 = 64²` is a statement about the transformation; whether it suffices depends on how much a publisher can
legitimately have. `ust_id` resolves to the second (`"ust:" YYYYMMDD "." HH [ MM [ SS ] ]`, tiers hour ⊃
minute ⊃ second), so the finest grid a declared cadence can place in one hour holds `3600` moments — and
`⌈3600 / 64⌉ = 57 ≤ 64`, so **every hour the addressing is able to express seals at depth 2**, with `4096 −
3600 = 496` of slack. `W_ABS² = P_ABS` ties the structural reach of two levels to the absolute partition
ceiling — which is why moving `W_ABS` would decouple two constants that currently agree.

**But an hour is ONE INSTANCE, and an instance is not the law (rev70).** Checking the window that prompted the
question leaves the real question unanswered: *can the addressing ever outrun the structure at all?* The domain
is not an hour, it is everything `ust_id` can name. Depth is the general function

  `depth(N) = ⌈log_{W_ABS} N⌉`, and a composition is expressible iff `depth(N) ≤ D_MAX = 8`.

The identifier's date part is `YYYYMMDD` with a four-digit year, so the whole addressable range is `0000-01-01`
through `9999-12-31` — **3 652 060 days**, and at second precision **`3 652 060 × 86 400 = 315 537 984 000`
moments**. That is the ENTIRE space the protocol can address at its finest tier.

**Theorem F.9.5-b (the depth bound strictly dominates the addressing).** `depth(315 537 984 000) = 7 ≤ 8`.
Therefore no composition over anything `ust_id` can name reaches the depth ceiling: the bound is not a limit on
what UST can express, it is strictly above it, and `64⁸ = 2.815 × 10¹⁴` leaves a capacity margin of ×892 over
the whole space. *Proof.* `64⁶ = 6.87 × 10¹⁰ < 3.155 × 10¹¹ ≤ 4.40 × 10¹² = 64⁷`, so seven levels suffice and
six do not; `7 < 8` is the claim. ∎

Read off the same function rather than asserted: an hour (`3600`) is depth 2, a day (`86 400`) depth 3, a year
(`31 536 000`) depth 5. The day figure agrees with the older reading of it as 24 hour-roots, which is a
composition of the same bound rather than a second rule.

**Why this matters more than the hour did.** A bound that merely *happens to fit* the window someone asked about
is a coincidence waiting to expire — the next question is a longer window and the answer has to be recomputed.
A bound proven above the WHOLE addressable space cannot expire, because there is no larger window to ask about.

**Realization (rev65).** Measured 2026-07-31: a flat attestation over 120 referents — one hour at the 30 s
cadence a live publisher declares — returns `INVALID E-BOUNDS`; the same 120 as two nodes of 60 under one root
verifies. The transformation is realized in the operator layer (`packages/ust-operator`), never in the base: the base
VERIFIES a composed tree and building one is a producer's job.

CLOSED 2026-07-31 by `2749655b` — protocol(rc.46): a worked example taught a refusable document — and the
fix was not the number (#101). In this tree a narration is written in the commit that fixes what it
describes, and blame places this paragraph there; noted 2026-08-05, appended rather than rewritten.

**Binding: realized** — *"#101 ADVERSARIAL: a capacity grant does NOT admit an over-breadth FLAT seal — capacity is VOLUME, breadth is STRUCTURE"*. The arithmetic was always over the §13 constants; what is now an obligation is that no declaration may reach a structural bound, which a check refuses rather than a sentence asserts.

### F.9.5-c The ROOT does not compose, so the ENUMERATION is what splits — and `root` becomes the completeness marker (#127)

F.9.5 says a breadth bound is escapable because `4096 = 64²` and a two-level tree carries the universe. That is
a statement about CAPACITY. It leaves open which of two compositions is meant, and the two differ in what a
CONSUMER must do — so the choice cannot be settled by preference.

**Theorem F.9.5-c.1 (the §7 root is not compositional, and compositionality is a property of the TREE, not of
this protocol).** §7 sorts the WHOLE leaf multiset before pairing. Hence for a partition `L = A ⊎ B` there is in
general no `f` with `root(L) = f(root(A), root(B))`.
*Proof.* Sorting is global: an element of `B` may sort between two elements of `A`, so the pairing of `L` is not
a refinement of the pairings of `A` and `B` taken separately. MEASURED on 120 leaves: `root(L)` and
`root([root(A), root(B)])` differ. ∎

**And the converse is REAL, which is why the theorem is stated about the tree rather than about seals.** §11.2
inclusion is a CONNECTOR: the tagged `ust:leaf`/`ust:node` walk is the bundled reference convention, not the
convention, and an operator running an RFC 6962 log supplies `opts.inclusionVerify` instead. That tree DOES
compose — order-preserving, split at the largest power of two — so `root(A ‖ B) = node(root(A), root(B))`
whenever `|A|` is a power of two. MEASURED on the same 120 leaves: the `64 ‖ 56` composition reproduces the whole
root exactly, while a `50 ‖ 70` split does not. A statement of the form *the root does not compose* is therefore
FALSE as a claim about this protocol, and true only of the bundled tree.

**Corollary (the enumeration argument does not depend on which tree an operator runs).** What survives both
trees is F.5u.1: `L` does not occur in the inclusion predicate. So the enumeration may be split under a
composing tree and MUST be split under a non-composing one, and in neither case does a consumer's inclusion
walk change. The escape below is therefore stated over the ENUMERATION — the one term both trees agree is not
an input to inclusion — and never over the root.

**Corollary (recursive roots are not merely inconvenient — they break §11.2).** If each node rooted its own
subtree and a parent's constituents were its children's `content_hash`es, the published top root would be a root
over CHILDREN, not over leaves. `Incl(d, r, π) = [ walk(H("ust:leaf", content_hash(d)), π) = r ]` then holds for
no leaf against that `r`, and inclusion would need a second, two-stage rule — one whose shape depends on how the
publisher chose to CHUNK its own seal. That is the publisher deciding the consumer's verification procedure,
which this protocol excludes everywhere else (F.5a.1).

**So there is exactly ONE root, over the whole leaf multiset, and what composes is the ENUMERATION.** This is
F.5u.1 read constructively: `L` does not occur in the inclusion predicate, so enumeration is the part that may be
split without touching what a consumer computes.

**Theorem F.9.5-c.2 (a partial enumeration cannot carry a root, and therefore `root` marks completeness).** Let
`N` be a node enumerating `C ⊊ L`. By F.9.5-c.1 no root of `C` bears any computable relation to `root(L)`, so
`N` has exactly two options: carry `root(L)`, which asserts *these are the constituents whose root is r* and is
FALSE for a proper subset, or carry no root at all. Hence the presence of `root` is not decoration — it is the
structural marker that a node's enumeration is COMPLETE. ∎

**Corollary (the completeness claim is positional, not conventional).** A consumer reading one node needs no
agreement about what a partial node "means": a node with `root` claims the whole set, a node without it claims
membership of the constituents it lists and nothing more. This matches the rule already in §9.2 — `root` is
REQUIRED for `set`/`anchor` and FORBIDDEN for `checkpoint`/`gap` — rather than introducing a second convention
beside it: the field was already carrying this meaning, and the theorem names what it was carrying.

**Corollary (the escape is general, and its limit is the depth law alone).** With enumeration splitting and one
global root, a seal over `N` leaves needs `⌈log₆₄ N⌉` levels, expressible iff `≤ D_MAX = 8`. Nothing in the
mechanism is specific to a window, a cadence, or an operator — the SAME construction is read at every `N`:

| window | leaves | depth |
|---|---|---|
| hour @ 30 s | 120 | 2 |
| day @ 1 s | 86 400 | 3 |
| month @ 1 s | 2 592 000 | 4 |
| **year @ 1 s** | 31 536 000 | **5** |
| century @ 1 s | 3 153 600 000 | 6 |
| millennium @ 1 s | 31 536 000 000 | 6 |
| **the WHOLE addressable space** | **315 537 984 000** | **7** |

**State the range by its CEILING, never by an example.** A reader shown the small end infers a small mechanism,
and every figure above except the last is an illustration — the last is the theorem. The ceiling is `64⁸ =
2.815 × 10¹⁴` leaves against an addressable space of `3.155 × 10¹¹`: a margin of ×892 with one depth level
never used, because `ust_id` cannot name enough moments to reach it (F.9.5-b). A year is the FIFTH of eight
levels, a millennium the sixth. There is no window this protocol can address whose seal does not compose.

**Theorem F.9.5-c.3 (the inclusion predicate has a constructive DUAL, and it belongs to the producer).**
`Incl(d, r, π)` decides a triple. For the predicate to be reachable at all, some party must PRODUCE `π`, and
nothing in the protocol did. Let `T` be a tree, `L` an ordered leaf list and `i < |L|`. Define `path_T(L, i)`.
The obligation is

> **∀ L, ∀ i < |L|.  Incl(L[i], root_T(L), path_T(L, i)) = true**

and — because a predicate satisfied by construction says nothing about the predicate —

> **∀ L, i, ∀ single-step mutation π′ of path_T(L, i).  Incl(L[i], root_T(L), π′) = false**

The second half is the load-bearing one. The first alone is satisfied by a builder and a verifier that share a
bug, which is the ordinary way a homemade tree walk passes its own tests for years.

**Where the dual may NOT live.** Not in the base. F.9.5-c.1 makes §11.2 inclusion a CONNECTOR — the bundled
`ust:leaf`/`ust:node` walk is *the bundled convention, not the convention* — so a base that shipped a
construction would re-assert exactly the normativity it dropped. Building is a producer act, as `sealTree`
already is on the other tree, and the two must be impossible to confuse: a path built under one tree and
checked under another fails with no statement of why, which is the worst available failure. Hence the produced
proof NAMES its scheme, and a connector claims a proof only under a scheme it implements.

**Corollary (an index is a natural, and narrowing it is a silent verdict flip).** RFC 6962 §2.1.1 defines the
path over naturals; the wire form is `uint64`. A builder using bitwise arithmetic coerces to signed 32 bits and
goes negative above `2³¹`, producing a path that is correct for every tree small enough to test by hand. The
verifier in this tree already met that defect on a live log. The dual must be written under the same discipline,
or the pair agrees — wrongly — on exactly the trees nobody checks.

**And the obligation is universal over IMPLEMENTATIONS, realized on one (#155).** The sentence above — *the
verifier in this tree* — names one verifier; the tree holds two independent climbs, because the browser verifier is clean-room and may
not import the connector. When the defect was fixed the enforcement was written to read the connector file BY
NAME, so the second climb was outside the rule — and a conformance check separately asserted that the browser
copy contained the narrowing form VERBATIM, having taken the 32-bit expression for a structural fingerprint of
RFC 6962's right-edge rule. The enforcement did not merely miss the second copy; it PINNED it. A sweep in July
would have gone red and read as the mistake.

Measured 2026-08-13: the shipped page could NOT confirm no-fork for any anchor written after the public log
passed `2³¹`, and had not been able to for sixteen days — reported to readers as a limit of their own browser
(F.5.1e). CLOSED 2026-08-13 — round 207 (#155).

A rule quantified over a class and enforced at a named instance is enforced nowhere else, and the clean-room
requirement GUARANTEES there is somewhere else. Two things follow, and they are the realization. The enforcement
must DISCOVER its domain — every site in the tree that climbs an externally supplied index, so that a third
implementation is inside the rule the day it is written rather than the day someone remembers it. And a check may
not pin an implementation to a literal the rule it serves forbids: behaviour survives translation between copies,
text does not, so text-identity is the wrong instrument for a claim about two implementations that must differ.

**Binding: realized** — *"#155 the web witness inclusion climb verifies an index above 2^31"*, which runs BOTH climbs on the same paths and requires them to agree; the discovery half is `tools/unbounded-index-gate.mjs`, which enumerates the climb sites from the tree rather than naming one, and is recorded as this round's test layer because a repository scan is a gate's work and not a conformance check's.

**Binding: pending — thelabmd/UST-Protocol#127** for the BUILDER; the tree claim itself is realized — *"F.9.5-c.1 the BUNDLED §7 tree does not compose — sorting is global, so a subtree root bears no computable relation to the whole and a partial enumeration cannot carry a root"* · *"F.9.5-c.1 ADVERSARIAL the RFC 6962 tree DOES compose at a power-of-two split — so \"the root does not compose\" is false as a claim about this protocol and true only of the bundled tree"* · *"F.9.5-c.1 and it does NOT compose at a non-power-of-two split — the composing property is conditional, so neither tree licenses a general claim"* · *"F.9.5-c.1 the two trees disagree on the SAME leaves — an operator's root is not reproducible by the bundled walk, which is why §11.2 inclusion is a connector rather than a protocol constant"*. What remains is a builder composing a seal over an arbitrary admissible `N`, a partial node carrying `root` REFUSED, and inclusion against the single published root exercised for a leaf under a composed enumeration.

**The obligation is universal over trees, and was realized on one (#139).** `path_T` is quantified over `T`; the
battery above instantiates it at RFC 6962 alone. The REFERENCE `ust:leaf`/`ust:node` walk — the construction a
verifier applies when NO connector claims the proof, and therefore the one with the widest reach — carried a
POSITIVE leg only: one leaf, one tree size. That is precisely the configuration the theorem names as worthless,
since a builder and a verifier sharing a bug satisfy it. The producer side of that tree already existed
(`AnchorBatch.build().proofFor`) and its root is the core's `merkleRoot` by construction; what did not exist was
the negative half. Now instantiated at both trees — *"F.9.5-c.3 REFERENCE tree: build-then-verify holds at the PROTOCOL sizes — 1,2,3,7,8, breadth 64, 65 where composition begins, and the 4096 ceiling (the positive half)"* · *"F.9.5-c.3 REFERENCE tree: every leaf reaches the SAME root, and that root is the core's merkleRoot — one tree, not one per query"* · *"F.9.5-c.3 REFERENCE tree: EVERY flipped direction breaks the proof (the load-bearing half)"* · *"F.9.5-c.3 REFERENCE tree: EVERY altered sibling hash breaks the proof"* · *"F.9.5-c.3 REFERENCE tree: a dropped step breaks it"* · *"F.9.5-c.3 REFERENCE tree: two steps transposed break it — order is load-bearing, not decorative"*. The sizes are the PROTOCOL's, and the first version of this battery got that wrong: it ran to 120 and called that the interesting width, which is the reference operator's HOUR — a fact about one deployment standing in for a bound. §13 fixes the numbers that belong here: breadth per node 64, array length 4096, and 4096 = 64² is where two-level composition lands. The odd-promotion sizes (3, 7) are in the set deliberately — the reference tree lifts an unpaired node with NO step in the path, an edge the RFC 6962 split never produces — and 65 is the first size that does not fit one node. At 4096 the leaf sweep is SAMPLED at named structural indices, because the builder recomputes the tree per query and the full sweep costs 38 s; the sample is stated in the suite rather than left silent, since a battery that quietly stops enumerating still reads as though it did.

**Corollary (a duplicated leaf makes the negative half vacuous, and the vacuity looks like a defect).** Where two
leaves are equal, a sibling can equal the node itself, and flipping `dir` concatenates the same pair — the
mutation is a no-op and the battery passes without testing anything. Measured while instantiating the above: a
leaf generator with a 16-value period left 92 of 120 mutations alive, and the first reading of that number was
*the builder is broken* rather than *the corpus cannot refute*. A mutation battery therefore states its leaf
distinctness as a precondition, exactly as [F.9.5-c.1] states its ordering.

**Theorem F.9.5-c.4 (a declared construction BINDS THE READER, and its absence names the reference).** F.9.5-c.3
gives the producer a dual and requires the emitted proof to NAME its tree. Naming is only half a mechanism: a name
nobody reads constrains nobody. Define, over an anchor proof `π`,

  `name(π) = π.anchor.inclusion.construction` when that member is a registered-form token, else `σ_ref`

where `σ_ref` is the bundled tagged walk (`ust:leaf`/`ust:node` over ASCII `sha256:` strings, §7/§11.2). `name` is
**TOTAL**: every proof has a construction, and a proof that declares none declares the reference one. Compatibility
is therefore a consequence of the definition and not a grandfather clause in code — every proof issued before this
theorem existed has `name(π) = σ_ref` and is decided exactly as before.

**Theorem F.9.5-c.6 (a construction is a TRIPLE, and the body belongs to it — not to the protocol).** F.9.5-c.4
gives a proof a NAME. A name is only useful if it resolves to something, and the something is not a pair of hash
functions. Define a construction as

  `σ = (leaf, node, body)` — a leaf rule, a node rule, and the GRAMMAR of what a proof must carry to be walked.

*The third member is forced, not stylistic.* The bundled construction hashes ASCII `sha256:` strings, and the
strings carry no position, so a walk cannot know which side a sibling is on: the body must state it, one direction
per step — `[{dir, hash}]`. RFC 6962 hashes raw digests and splits at the largest power of two below `n`, so the
side of every sibling is a FUNCTION of `(index, tree_size)`: the body carries those two numbers and the bare
sibling list, and directions in it would be redundant data a producer could contradict. Neither body is a
simplification of the other, and no single grammar covers both without carrying, for one of them, a field that its
own walk must ignore. A protocol that fixed ONE body would therefore fix the tree — the exact normativity §11.2
gave up when it made inclusion a connector (F.9.5-c.1).

**Corollary (registering a name registers the grammar).** Since `σ` includes `body`, an entry in the construction
registry that names only hash rules is incomplete: two implementations agreeing on `leaf` and `node` can still
fail to exchange a proof, because neither knows what the other will send. That is not hypothetical — it is the
measured state of this tree before this theorem: one package emits `{index, treeSize, hashes, rootHash}` and
another reads `{index, tree_size, hashes}` beside a prefixed `root`, both under the same name, and a proof handed
from the first to the second is answered **false** rather than "I cannot read this" (thelabmd/UST-Protocol#149).

**Corollary (ONE carrier, and why it is not the Locator).** The body travels in `π.inclusion`, beside `root` and
`path`, never inside `π.anchor`. §11.2 holds membership and substrate to be two INDEPENDENT proofs that must not
be conflated, and `anchor` is the substrate's Locator: a tree's grammar placed there would make the publisher's
membership evidence a field of the substrate that merely witnessed its root. The reference construction keeps its
body in `path` — that member predates this theorem and every proof ever issued uses it, so `σ_ref`'s grammar IS
`path`, and no reissue is implied for anything already published. ∎

**Binding: pending — thelabmd/UST-Protocol#149** for the CARRIER move: the shipped Rekor connector still reads the
body from `π.anchor.inclusion`, so until it is moved this theorem states where the body belongs while one
implementation reads it elsewhere. The naming half is realized — *"F.9.5-c.5 a DECLARED foreign construction is not walked with the reference tree — the answer is withheld, not minted"*.

**Theorem F.9.5-c.5 (evaluating a construction one was not asked for is not evidence).** Let `C_V` be the
constructions a verifier `V` can compute — those it implements natively plus those an installed connector claims.
Write `Incl_V(π) ∈ {⊤, ⊥, ⊘}`, where `⊘` means the predicate is UNDEFINED for this verifier.

  **If `name(π) ∉ C_V` then `Incl_V(π) = ⊘`.** Not `⊤`, and not `⊥`.

*Both halves are load-bearing, and both are MEASURED violations today (2026-08-11).*

*The `⊤` half.* A proof declaring `construction: "acme-tree-v9"` — or `42`, `null`, `{}`, `["x"]` — whose `path`
happens to satisfy the reference walk is answered `inclusion: true` by this core, which reads no name at all
(`grep -c "scheme" packages/ust-protocol/index.mjs` → 0). The core confirms membership under a name it never
examined. What it proved is membership in a `σ_ref` tree; what it reported is membership, unqualified, to a
consumer reading the declaration.

*The `⊥` half.* Conversely a proof honestly built under a foreign construction is walked with `σ_ref` and answered
`inclusion: false, "inclusion path does not reach root"` — the proof blamed for the verifier's inability, which is
the refusal-becomes-verdict class closed in the core once already (#144).

**Corollary (the determinism §11.2 requires is what actually breaks).** §11.2 rests agreement on determinism — in its own words, two consumers
loading the same DECLARED profile reach the same verdict. Under the measured behaviour, one
consumer holding a connector for `σ` and one holding none return **different** verdicts on the SAME document, and
neither reports uncertainty — the first `⊤`, the second `⊥`. Disagreement between honest verifiers is a strictly
worse failure than either wrong answer alone, because no third party can adjudicate it from the document. ∎

**Corollary (`⊘` is DISTINGUISHABLE, and the model says nothing about how).** The codomain of `Incl_V` has three
members and `⊘ ≠ ⊥`. What the model requires of any realization is exactly this and no more: **no reader of the
reported answer may be able to reach `⊤` or `⊥` from `⊘` without an explicit decision.** Whether that is achieved
by omitting a member, by a distinct type, or by a channel of its own is an ENGINEERING choice, and it belongs to
§11.2 and to the code — not here.

*This paragraph replaces one that had it backwards, and the replaced version is described rather than deleted
because the error is instructive.* The first draft justified the chosen shape — omission — by how the consumers in
THIS tree happen to read the member (some strictly, some loosely, so a truthy third value would be misread). That
is a true observation and it is not mathematics: it derives a requirement from the habits of an implementation,
which inverts the direction the whole ladder runs in. **MATH LEADS.** If a realization cannot distinguish `⊘`
without a wrong answer leaking, that is a defect in the realization, and the theorem is the instrument that says
so — it is not a reason to write the realization's convenience into the theorem. The engineering argument survives
where it belongs, one layer down, as the reason §11.2 chose omission.

**Corollary (what `⊘` may NOT do to the tier).** `⊘` withholds; it never lifts. Anchored TIME still requires `⊤`
from an evaluated construction AND the substrate seam, so an unsigned, unverified name can lower or hold the anchor
coordinate and can never raise it. Stated over the anchor coordinate only: on the §14 verdict lattice `INVALID` and
`INDETERMINATE` are deliberately incomparable (#144), and this corollary does not order them.

**Domain (enumerated, not sampled).** This theorem quantifies over OBSERVATIONS of `Incl` by a consumer, and
that set is machine-enumerable: `grep -n "verifyAnchorCore" packages/ust-protocol/index.mjs` → **3 call sites**
(the embedded-proof branch of `verifyCore`, the public `verifyAnchor`, and `anchoredByProofs` on the witness
path). All three are checked, and the third is checked separately because it is reached only through
`witnessNoFork` and decides `authoritative` against `consumer-override`.

*Why this line exists, when no other theorem here carries one.* Round 201 realized this theorem and asserted it at
ONE of the three sites; the other two were edited and not checked, and the suite was green. The claim is universal
and the evidence was an instance — the failure thelabmd/UST-Protocol#150 was opened to make impossible in general.
Until that gate exists this line is the manual form of it, and it is written as a QUERY rather than a list so a
fourth call site changes the count rather than hiding behind prose.

**Realization (round-235 — `⊘` is a statement about the TIME carrier, and the document's verdict is not that carrier).** Round 201 realized this theorem against the question it was asked: *is the document guilty of the verifier's inability?* The answer — `INDETERMINATE`, never `INVALID` — is right and stands. What was never asked is the SCOPE of that `INDETERMINATE`, and the unqualified form is what got built: at `verify`'s anchor step a withheld `Incl_V(π) = ⊘` returns from the whole function, before name authority is resolved, so identity, capacity, no-fork and the witness result are not withheld but NEVER DERIVED. Measured 2026-08-16 on a live document whose publisher had done everything right: with no proof at all it resolves `VALID:HIGH`; with its own correct, substrate-final proof attached and no connector installed, `INDETERMINATE` — attaching true evidence lowered the verdict, which inverts the incentive the anchoring layer exists to create. This is round-233's mechanism one axis over, and rev92's algebra decides it identically: membership-in-a-committed-root is a predicate over the TIME carrier, while the identity carrier is `(genesis, key log, witness)`; neither is a factor of the other, so `⊘` on the first may not remove the second. The three-valued discipline round-233 established transfers with it — **no proof**, **proof verified**, and **proof present but unreadable** are three states, and collapsing the third into the first is the mirror error of collapsing it into a withheld verdict: only the third is repaired by installing a connector, which is why `unsupported_construction` is a `faculties` term and must be REPORTED, never merely absent. **The asymmetry is REAL here and must not be swept away**: where a consumer has asked for the time coordinate itself — `requireAuthoritative`/`requireAnchored`, whose refusal `E-ANCHOR` names a downgrade the consumer forbade — `⊘` is a refusal of exactly what was requested and stays one; and N9 (a document may not postdate its own anchor) is a predicate over an anchor time that `⊘` never produces, so it is silent rather than satisfied. A sweep that turned every `⊘` into a report would break both. The scope defect is **CLOSED** (2026-08-16, round 235): the withheld answer is carried on the coordinate instead of returned as the document's verdict, and the pair of checks that pinned the symptom was re-aimed at the relation — the verdict equal to the no-proof run, the coordinate not. What stays **OPEN** is the faculty half tracked as thelabmd/UST-Protocol#172: the shipped web verifier installs no connector for the one construction a live operator publishes, so it meets this state by default rather than by accident of configuration.

**Realization (round-236 — `⊘` has a THIRD source, and it is the calling MODE rather than the construction).** `C_V` was read as a property of the verifier alone: which constructions it implements, plus those an installed connector claims. A host adds a second dimension the definition never carried — whether the verifier can OBSERVE that connector's answer in the mode it is being called in. A connector whose computation is asynchronous returns a promise to a synchronous call site, and the value the seam receives is not `⊤`, not `⊥`, and not a construction name it fails to recognise: it is the SAME undefined the theorem already ranges over, arriving by a different road. Measured 2026-08-16 on the live document of round-235: the seam answered `inclusion: false`, `verify` read that as a path that does not reach its root, and the verdict was **`INVALID`** — a document called forged because the reader's own connector was a promise. Both halves of the theorem are violated at once: the `⊥` half directly, and the corollary on determinism twice over, since two consumers holding the SAME connector now disagree by which door they entered. The consequence is not merely a wrong label. `sha256` is asynchronous in every browser, so EVERY browser realization of any construction is a promise by construction; under `Incl_V(π) = ⊥` the class of hosts that can admit a foreign construction at all is empty, and the tier ceiling of an entire host family is decided by an artifact of the calling convention rather than by any evidence. **The repair is a widening of the observation, not of `C_V`**: the asynchronous door resolves the connector once and hands the settled answer to the synchronous core — exactly as the substrate seam already does, receipt bound to the `(anchor, root)` it was obtained for, so a resolved answer cannot be replayed against a different pair. Under that reading `C_V` recovers its stated meaning (what the verifier can compute) and the mode stops being a hidden second factor of it. **What stays `⊥`**: a connector that RETURNS `false` has computed and refused, and that is a verdict about the proof; a connector that throws, or returns a non-Boolean, is a not-ours module violating its contract and is `⊥` by the trust-boundary law. Only **cannot be observed here** is `⊘`, and the sync door keeps saying so — withheld, never refused. **CLOSED** (2026-08-16, round 236): the asynchronous door pre-resolves the inclusion seam under the same identity binding the substrate seam uses, and a promise reaching the synchronous door is withheld rather than refused. What remains **OPEN** is a question this repair does not answer and must not be read as answering — whether a host that can compute a construction only asynchronously should be able to reach `⊤` through a door a caller chose, since the choice of door is now load-bearing for the tier and nothing makes a caller aware of that.

**Binding: realized** — *"F.9.5-c.5 a DECLARED foreign construction is not walked with the reference tree — the answer is withheld, not minted"*, *"F.9.5-c.5 ADVERSARIAL: a declared foreign construction over a reference-satisfying path no longer reports inclusion"*, *"F.9.5-c.4 a proof declaring NO construction is decided exactly as before (the total projection, not a grandfather branch)"*, *"F.9.5-c.5 THROUGH verify(): a foreign construction withholds the ANCHOR coordinate and nothing else (round-235)"*, *"F.9.5-c.5 THROUGH verify(): an UNREADABLE proof is not the same state as NO proof — the third state is reported, never collapsed"*, *"F.9.5-c.5 THIRD call site (witness): a witness anchor whose construction this build cannot compute leaves no-fork UNPROVEN, never confirmed"*.


**Conformance (math ⇒ spec ⇒ code ⇒ green vector, once realized).**
- a composed seal over `N > 64` verifies, and the leaf inclusion path resolves against the ONE published root;
- a node enumerating a proper subset and carrying `root` is refused;
- the composition is exercised at two different `N` on different levels, so nothing is fitted to one window.

### F.9.6 Calibration of the numerical constants

The model derives the INEQUALITIES the constants must satisfy; it cannot make one assignment uniquely
necessary. Concrete values are calibration parameters with explicit, falsifiable premises:

- `F_ABS = ⌈√P_ABS⌉ = ⌈√4096⌉ = 64` — the minimal uniform branching factor representing the full partition
  universe in a two-level tree (the two-level requirement is the declared design premise; 64 then FOLLOWS).
- `A_ABS = P_ABS = 4096` — one canonical operation can hold the full universe, no slack.
- `B_ABS = η · P_ABS · s̄ = 4 × 4096 × 4 KiB = 64 MiB` — declared premises: target partition payload
  `s̄ = 4 KiB`, encoding-and-safety factor `η = 4`. Falsifiable by vectors and memory benchmarks.
- `B₀ = 1 MiB` — the power-of-two floor of `min` over the baseline environment class 𝓔₀ (browser, agent tool,
  CLI, message/file transport, serverless) of each environment's transport cap, `(M_e − r_e)/α_e` and
  `T_e/β_e`. The benchmark matrix that pins this minimum is an OPEN calibration item; until published, 1 MiB
  is a declared engineering premise, not a derivation.
- `D_ABS = 8` — bounded by the worst-case recursive canonicalization frame against the smallest baseline
  stack; premise pending the same matrix.
- `K_ABS = 256` — a linear resolution-cost budget `⌊(T_K − c₀)/c₁⌋` rounded to a power of two; the re-genesis
  epoch means it bounds one resolution epoch, never a publisher's history.
- `W_default = 32` — a per-call walk depth (a caller budget), not a cap on how long a provenance chain may
  exist (rc.12 naming).
- `T_witness = 30 s` (default) — the `T_v` (time) coordinate of `ρ_v` for a WHOLE witness-resolution operation, so a
  legal but adversarial anchor fan-out (`W_active × A_pergenesis` sequential substrate calls, each honestly under the
  per-leaf `T_leaf = 10 s`) cannot amplify to `≈ W_active · A_pergenesis · T_leaf` (`16 × 8 × 10 s ≈ 21 min`) — the
  attack the per-leaf bound alone did not cover. It is a VERIFIER-OWNED ceiling, not a protocol constant nor a
  publisher declaration (F.9 assigns `ρ_v` to the verifier; a ceremony declaration can never set it — *assurance is
  never self-declared*): the effective budget is `min(T_witness_default, ρ_v.time_consumer)` — a consumer may only
  TIGHTEN it, and the consumer's `maxWitnessOpMs` is threaded through the PUBLIC entry (`resolveByDiscovery → witnessNoFork
  → anchoredByProofs`), not only the leaf — rev23 wired the leaf and the principal integration dropped it, so the policy
  was unreachable; rev27 closes that (*"round-26 P1-03/L4 resolveByDiscovery THREADS the consumer witness budget (maxWitnessOpMs) through the PUBLIC entry → a tight budget resource-limits the witness, no false served-list HIGH (F.9 ρ_v)"*). Exceeding it is `INDETERMINATE(resource_limit)` per F.9.3 (`C_v(R) ⋠ ρ_v`), naming the effective budget —
  a REFUSAL to finish, never a truncation of the served list and never a verdict about the data. `30 s = 3 · T_leaf`
  is a declared engineering premise (a few genuinely-slow real substrate calls in series), recalibratable per §F.9.6;
  the LAW (T_v is a resource coordinate; over-budget ⇒ resource_limit) is derived, the constant is calibrated.

**The model derives the law; benchmarks calibrate the constants.** While `Ω` and `Fₜ` are purely mathematical
objects, the resource bounds `ρ_v` and the numeric constants (`B₀`, `κ`, …) are ENGINEERING PARAMETERS
instantiated for the declared target environment class `𝓔₀` — the platonic and the physical are joined only
through explicitly published premises. A change in the target environment class or the measured amplification
requires recalibration — not a reinterpretation of the mathematics.

---

### One-paragraph summary

Model the world as a filtered measurable space `(Ω, F, {Fₜ})` whose filtration **is** the append-only anchor
journal. Fields are coordinate maps; a record fixes the publisher's *measurement* of them, never the truth. To
**verify** is to test **measurability**: `VALID:LIGHT/HIGH/TOP` names the FINEST of three nested σ-algebras (the
highest tier reached)
(`𝒮_LIGHT ⊆ 𝒮_HIGH ⊆ 𝒮_TOP`) with respect to which the record is measurable-and-true — the floor from the
document alone, HIGH adding the name-authority σ-algebra, TOP adding the filtration itself. Two conforming
verifiers agree because the verdict is a single-valued measurable function (I4); a verifier lacking the needed
σ-algebra returns INDETERMINATE, never INVALID. Probability is degenerate in the core and load-bearing only across
the measurement-vs-reality gap — which is precisely the line UST refuses to cross.
