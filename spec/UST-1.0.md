<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Universal State Transcript (UST) — Protocol Specification, Version 1.0

*This specification text is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](../LICENSE-SPEC). Reference code in this repository is licensed Apache-2.0. Use of the name **UST** / **Universal State Transcript** and the **UST-compatible** claim: see [TRADEMARK.md](../TRADEMARK.md).*

> **Release candidate — `1.0.0-rc.18`.** This specification has been extensively red-teamed; an independent
> external cryptographic audit is pending. It is subject to change until `1.0.0` final (rc.2 folded in two external reviews — 6 impl findings + spec edge cases + removed domain-less `computed`; rc.3 aligned impl to §3.1 pinned + Y3; rc.4 closed a 4th external audit (ChatGPT 5.5 Max): key-binding by KEY not string, TOP needs a genesis origin, embedded proofs fail-closed, class↔schema enforced, canon strict on names too, raw-bytes verify boundary, ust_id valid frames, and REMOVED secret-url as a privacy mode; rc.6 closed a 5th external audit STRUCTURALLY — the §14a obligations table (every commitment-bearing member recomputed: +`E-SEED`), a typed identity namespace (dns-name | self-certifying key-id), real-calendar semantic consistency, document-tier vs range-completeness separation, MTI registry discipline, one version source; rc.7 explicit `completeness:not_evaluated`; rc.8 admissibility pins (duplicate refs, key-log
ceiling, layer availability); rc.9 edge pass (full reserved-name registry, verified-node budget, strict-Z);
rc.10 partition-capacity ladder (floor 64 / genesis-declared ≤ 4096); rc.11 SIZE ladder + VOLUME-vs-STRUCTURE
classification; rc.12 canonical size semantics (UTF-8 signed-content metric), trusted capacity grants,
`resource_limit`). Pin exact versions.

**UST is trust infrastructure.** It gives any machine-published statement about the state of the world its own
VERIFIABLE trust — WHO asserted it, WHAT exact bytes, for WHICH time-frame, WHEN, and FROM WHAT — checkable
offline by anyone, without trusting the transport or the publisher. As DNS names hosts and TLS secures
channels, UST makes machine-published STATE trustworthy: a public substrate for trust in world-state, in
graduated tiers (LIGHT / HIGH / TOP, §3.1). Every mechanism below serves that single job, and every clause is
judged by ONE question — *how much trust does this actually earn, and does the protocol say so honestly?* A
tier must never let a consumer read "signed" as "true," "anchored" as "correct," or "agreeing" as "independent."

Status: **Normative specification — 1.0 REV 29 (2026-07-13).** The SECURELY-STRUCTURED (namespaced) base that
closed all red-team findings STRUCTURALLY (I3 collision unrepresentable, I1 whole-State signature by
construction, no stored-hash footgun), with ALL v0.29 FEATURES merged IN (not a flat-wire revert): per-partition
captured/computed hashing (cross-engine corroboration for computed parts), `parent_ust` (hour-close timing),
per-partition privacy incl. mixed open+closed in one shard, shard-chain LAYERS + selective disclosure.
Features are capabilities orthogonal to wire shape; this keeps the structure's security AND every retained
029 function (secret-URL was removed as a privacy mode in rc.4 — see §10). Flat-wire attempt archived (`UST-1.0-flat-evo-archive.md`); feature audit `rnd/feature-audit-029-vs-v1.0.md`. A measure-theoretic semantics (NON-NORMATIVE) is in `UST-1.0-formal-model.md`.
Model (tiered): the LIGHT floor mandates only a signed, canonical, addressable State (identity+
integrity, self-contained); NAME-AUTHORITY (genesis/key-log), TIME (anchoring) and COMPLETENESS are HIGH/TOP
operator tiers, verified when present and reported as verification STRENGTHS — never a floor gate (§3.1). The
protocol fixes the mechanism; substrate/schema/completeness are operator choices (§20). History: Appendix B.
Conventions: The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY are to be
interpreted as in RFC 2119 / RFC 8174 when in ALL CAPS.

This document is self-contained: a competent engineer MUST be able to build a conforming producer and a
conforming verifier, in any language, from this text and the referenced test vectors alone, and obtain
byte-identical results.

---

## 1. Abstract & scope

UST defines the format and verification of a **State Transcript**: a signed, content-addressed, time-frame-
addressed record of the form

> *publisher `P` asserts data `S` for time-frame `T`, derived from provenance `R`.*

A conforming verifier establishes — offline, without trusting the transport or the publisher's honesty about
content — **what exact bytes** for **which frame**, and **who signed** it (at LIGHT the signing key travels
with the record, §7). At HIGH the `domain_shard` NAME is verified authoritative (genesis, §12); at TOP **when**
(anchored, §11) and completeness are added — each reported as a verification STRENGTH. Identity & integrity are always self-contained; time, completeness, and
name-authority-at-scale are operator GUARANTEES surfaced as verification STRENGTHS (§16).

### 1.1 What UST is NOT (normative scope limits)
- NOT an oracle: a valid transcript attests that `P` recorded `S`; it does NOT assert `S` is true of the world.
- NOT a safety boundary: `data` content is untrusted third-party input (§18.4). Verification never implies it is safe.
- NOT a consensus system or blockchain: no token, no global agreement; time comes from an external append-only log.
- NOT a transport or discovery system: how records are fetched is out of scope and MUST NOT affect verification.

### 1.2 Layering
The protocol fixes the **mechanism** (§4–§14). Operator choices (partition schema, substrate, cadence, bounds
within ceilings) live in an **operator profile** (§20). The LIGHT floor's security (I1/I3/I4/I5/I6/I9/I10) is
never operator-optional; name-authority (HIGH) and anchored time (TOP) are document tiers; completeness is a SEPARATE range verdict over a stream, not a document tier (§3.1/§11.3).

---

## 2. Terminology

- **State** — the canonical, signed object that carries all asserted content (§4.2). The unit of authority.
- **Transcript** (or **document**) — a State plus its detached Signature plus an OPTIONAL self-contained
  time `proof` (§11.2). The unit of exchange. No unsigned human-authoritative field exists (N3).
- **Genesis** — the witnessed first key that establishes a publisher's authority over `domain_shard` (§12.1).
- **Anchor proof** — a Merkle inclusion path from a State's `content_hash` to an anchored root + the log
  locator, letting a verifier confirm time with no mutable lookup (§11.2).
- **Publisher** — the entity identified by `domain_shard`; the sole authority over a State's meaning.
- **Partition** — one named data object inside the State (e.g. `observational`, `deterministic`).
- **Anchor** — a commitment of a content hash into an external append-only log yielding un-backdatable time.
- **Key log** — a publisher's append-only, anchored record of its signing keys (§12).
- **Verifier** — software that executes §14 and returns VALID or a specific error (§15).
- **Content hash** — a DOMAIN-SEPARATED SHA-256 (§7): `H_t(x) = "sha256:"||lowerhex(SHA-256(ascii(t)||0x00||x))`
  for a per-kind tag `t`. A State's `content_hash = H_state(canon({ust, state}))` (the signed content, §7). There is no untyped hash in UST.

---

## 3. Design invariants (the contract)

A conforming implementation upholds all of the following. Each is stated with the failure it forecloses.
These are testable (§16) and are the ship-gate: v1.0 is "ready" iff every invariant holds everywhere.

- **I1 — Total signature coverage.** Everything a transcript asserts is inside the State, and the State is
  signed in its entirety. Nothing that affects meaning is unsigned. *Forecloses: unsigned timing/provenance/
  version/root tampering; two-truths documents.*
- **I2 — Mandatory signature (floor) + tiered name-authority.** A transcript without a valid signature has NO identity and
  MUST be rejected. Identity derives from the signature, never from the fetch transport. *Forecloses:
  off-substrate impersonation.*
- **I3 — Namespace isolation.** Identity, data, provenance, time, and privacy occupy disjoint reserved
  namespaces; a partition name can never occupy an identity slot. *Forecloses: structural field-collision
  forgery.*
- **I4 — One canonical form.** Exactly one serialization is valid for a given State; it is string-only,
  NFC-normalized, duplicate-free, and bounded. Two conforming verifiers ALWAYS agree. *Forecloses:
  canonicalization ambiguity as a dispute/equivocation weapon; cross-language divergence.*
- **I5 — Bounded structure.** Depth, size, breadth, and chain length are hard-capped; chain walks detect
  cycles. *Forecloses: verification denial-of-service by crafted structure.*
- **I6 — Blinded privacy.** A private data's commitment is high-entropy-blinded; public parties learn
  existence and time only. *Forecloses: brute-force recovery of low-entropy private state.*
- **I7 — Immutable-rooted trust.** The verifier's root of trust is the append-only anchor (and the anchored
  key log), never a mutable fetch (DNS, `.well-known`, a git repo). *Forecloses: discovery/profile/key
  poisoning under an "immutable" claim.*
- **I8 — Bound source identity.** A provenance source name is authenticated to a real source or explicitly
  marked unauthenticated; a bare name is never presented as attribution. *Forecloses: reputation laundering.*
- **I9 — Provenance ≠ truth ≠ safety.** Verification attests origin, integrity, time, and lineage — nothing
  about correctness or safety of data. Consumers MUST treat data as untrusted. *Forecloses: signed
  content laundering (incl. prompt injection into agents).*
- **I10 — Fail-closed, version-stable.** Any inability to complete a check yields rejection, never
  acceptance; verification behavior does not branch on any attacker-controllable field. *Forecloses:
  fail-open under load; downgrade.*
- **I11 — Named-genesis identity authority.** A publisher's AUTHORITY over `domain_shard` is established by a
  witnessed genesis (§12.1) — anchor time/order alone never confers name authority. (Sequence COMPLETENESS is
  an operator GUARANTEE, §11.3, not a universal invariant — it applies only where an operator declares a
  sequenced stream.) *Forecloses: rival key-log impersonation.*
- **I12 — Self-contained time.** A transcript's anchored time is verifiable from an inclusion proof it
  carries, with no mutable lookup. *Forecloses: anchor-discovery via a mutable index.*
- **I13 — Domain-controlled authority + time-bound revocation.** Name authority roots in domain control (not
  key possession), and a revoked key's signatures are judged against the revocation's anchored window.
  *Forecloses: stolen-genesis identity capture; back-dated signatures by a compromised key.*
- **I14 — Bounded verification.** Verification runs at a declared depth (DEFAULT depth-0: the local State is
  fully verified, referents are present-but-unverified); deeper walks consume a caller-supplied finite budget.
  *Forecloses: verification fan-out DoS.*

---

### 3.1 Trust tiers — LIGHT / HIGH / TOP (the adoption floor stays light)

Verification is TIERED so the FLOOR is adoptable in a minute, while the SAME document upgrades to notary-grade
trust with no format change. Analogy: a self-signed TLS cert (LIGHT — encryption, no CA authority) → a CA-signed
cert (HIGH — name authority) → an EV / CT-logged cert (TOP). Every verification EMITS the tier IN THE VERDICT
itself — `VALID:LIGHT` / `VALID:HIGH` / `VALID:TOP`, never a bare `VALID` — so a consumer cannot read "valid"
without reading valid-AT-WHAT; nothing silently claims trust it did not establish.

- **LIGHT — trust in a minute (THE FLOOR).** A signed, canonical, addressable state document. *Publish* =
  generate a keypair, sign your canonical JSON, serve it (the pubkey travels in `sig.pub`). *Verify* = recompute
  the canonical + per-partition hashes (integrity) + strict-Ed25519-verify the signature against the carried
  (or out-of-band pinned) key. Identity strength = `self-asserted` (the key signed it; `domain_shard` is a
  self-asserted LABEL) or `pinned` (TOFU / pinned key). NO genesis, NO key log, NO anchor required. This is the
  0.29-light floor + the ONE justified hardening (a mandatory signature). One library call each way. **A LIGHT
  consumer MUST NOT attribute or display `domain_shard` as the publisher (Y3): LIGHT authenticates a KEY, not a
  NAME — a griefer floods `self-asserted` docs under any label for free. Name attribution requires HIGH+.**
- **HIGH — under a product.** + a genesis-rooted, self-signed key log (§12) → real NAME AUTHORITY (identity
  strength `authoritative`), key rotation/revocation, an operator profile (§20). What a service operator runs.
- **TOP — a product built OVER HIGH (the notary).** + a witnessed/transparency genesis + un-backdatable time
  (anchoring, §11) + sequenced-stream completeness (§11.3). The full notary — exactly noosphere.

**Floor invariants (LIGHT, always MUST):** I1 (whole-State signature), I3 (namespace isolation), I4 (one
canonical), I5 (bounds), I6 (blinded privacy when used), I9 (data untrusted), I10 (fail-closed). **Tier
invariants (HIGH/TOP, strengths):** I2's NAME authority, I7, I11, I12, I13 — verified WHEN present, reported as
strengths, never a floor gate. **Rule:** any rule that raises the floor above "sign your canonical addressable
JSON" is a regression against adoption and belongs in a TIER, not the floor.

---

## 4. Data model

### 4.1 Transcript (unit of exchange)
```
Transcript := {
  "ust":    "1.0",          // REQUIRED FIRST — protocol + version marker; the document self-identifies as UST
  "state":  State,          // REQUIRED — the signed state object (§4.2)
  "sig":    Signature,      // REQUIRED — detached signature over canon(transcript minus sig/proof) = canon({ust,state}) (§7)
  "proof":  AnchorProof     // OPTIONAL — self-contained time evidence (§11.2): Merkle inclusion path + anchor locator
}
```
`ust` announces the protocol (like a media type / magic marker) and is SIGNED (part of the signed content, §7 —
so no downgrade). `state` + `ust` are the inputs to identity/integrity; `proof` (when present) supplies time.
There is NO unsigned human-rendered field: a renderer derives display from the SIGNED `state` only. A verifier
REJECTS unknown top-level members (E-MALFORMED, fail-closed). (`view` was DELETED — an unsigned, human-authoritative surface is a
presentation-layer two-truths injection with no security benefit, N3.)

### 4.2 State (unit of authority — everything asserted, all signed)
```
State := {                                   // the top-level `ust` (§4.1) is signed alongside this object
  "id": {                                    // REQUIRED — identity & address
     "domain_shard": string,                 // publisher identity — a TYPED namespace (§4.3a): a dns name, or a
                                             // self-certifying key-id (`sha256:<hex64>`) that MUST equal `key_id`
     "ust_id":       string,                 // time-frame address (§8)
     "key_id":       string,                 // the signing key's identifier in the publisher key log (§12)
     "class":        "observation"|"attestation"|"derivation",  // intent tag; does NOT alter §6/§7 rules
     "parent_ust":   string                   // OPTIONAL — coarser frame this shard refines (§8.1); hour-close timing
  },
  "time": {                                  // REQUIRED signed fields (assertion); anchored time is a STRENGTH (proof optional, §11.2)
     "generated_at": string,                 // RFC 3339 UTC instant of sealing
     "valid_from":   string,                 // RFC 3339 UTC
     "valid_to":     string                  // RFC 3339 UTC-Z; valid_from ≤ valid_to ≤/≥ generated_at per §11; NO freshness grace in 1.0 (freshness = the anchor, P10)
  },
  "data":    Data,                     // REQUIRED — partitions (§4.4); each has a KIND (captured/computed) and a VISIBILITY (public/private) — privacy is PER-PARTITION
  "hashes":     { "<partition>": ContentHash }, // REQUIRED — per-partition hash (§4.4), recomputed by the verifier
  "provenance": Provenance                   // OPTIONAL — chains, source anchors, seed, layer seed (§9)
}
```
**Reserved top-level State keys:** `ust, id, time, data, hashes, provenance`. **Reserved `id` keys:**
`domain_shard, ust_id, key_id, class, parent_ust`. **Reserved partition-envelope keys:** `kind, value, privacy, commit, enc`. A State containing any other key at these levels, or a duplicate key
anywhere, is malformed (E-MALFORMED, §15). Partition names live ONLY inside `data` and thus can never
collide with an identity or provenance slot (I3).

### 4.3 Rendering (derived, not a field)
There is no unsigned convenience field (N3). Any human/agent rendering is COMPUTED from the signed `state`
by the consumer. If a display hint is genuinely needed it goes in a SIGNED partition (then it is data —
untrusted per I9, but tamper-evident). Nothing a human sees is outside the signature.


### 4.3a Identity namespace (typed `domain_shard`)

`domain_shard` carries ONE of two identity types, distinguished by FORM (no extra field, no ambiguity):

- **name** — any non-key-form label; NOMINALLY a DNS name (`example.com`). At LIGHT the label is a
  self-asserted CLAIM and is NOT validated as DNS syntax — validating a claim's spelling would prove nothing
  (Y3: never display it as the publisher). It is at HIGH that the name becomes real: genesis + key-log (§12)
  bind a DNS name to the signing key, and only a DNS name can be so bound.
- **self-certifying key** — the string form of a key-id (`sha256:<64 hex>`). The identity IS the signing key:
  a verifier MUST require `domain_shard == state.id.key_id` (mismatch ⇒ `E-MALFORMED` — claiming ANOTHER key's
  shard is malformed, an obligation, not a convention). No name is claimed, so there is nothing to over-read;
  this is the native LIGHT identity for keys with no domain (browser signers, ephemeral agents).

A verifier reports the mode (`identity.mode: "name" | "key"`) alongside the strength. A key-form shard never
resolves genesis (there is no name to bind); name authority (§12) applies to `name` mode only.

### 4.4 Data — per-partition kind, visibility & hashing (029 feature, in the namespaced shape)
`data` is a map of one or more **partitions**; names are operator-schema, unique, non-reserved (I3 — names
live ONLY under `data`, cannot collide with identity). Count ≤ 64 (§13). Each partition is an envelope:
```
Partition := { "kind":"captured"|"computed", "value": { <string leaves> } }               // PUBLIC
            | { "kind":"captured"|"computed", "privacy":"blinded"|"encrypted",
                "commit": ContentHash [, "enc": {"alg":string,"key_id":string,"ct":b64url}] }  // PRIVATE
```
**Per-partition hashing (UNIFORM).** Each partition has its OWN hash in the signed `hashes` map. The preimage is
the SAME for every partition — it ALWAYS binds `domain_shard`, and the partition NAME is carried as a VALUE
(`partition:`), never as a key, so a partition name can never overwrite a protocol field:
`H_shard(canon({domain_shard, ust_id, partition: <name>, value}))`.
- `kind` (`captured` = witnessed · `computed` = derived) is a DESCRIPTIVE tag and does NOT change the hash.
- The old domain-less `computed` mode (hashing WITHOUT `domain_shard`, so independent engines got an IDENTICAL
  hash for "cross-engine corroboration") was REMOVED in rc.2: that agreement was FORGEABLE (a publisher COPIES the
  domain-less hash to fake agreement — as this spec already noted) and FRAGILE (a `"3.14"` vs `"3.140"`
  string-format divergence breaks it though the values are equal). Real corroboration compares two
  publisher-BOUND values a layer up (each bound to its own domain — non-forgeable), never a shared hash.
- A private partition's hash is over its `commit`.
- The `hashes` map is inside the signed State (I1), is an EXACT bijection with `data` (one entry per
  partition — §14 step 2, G19), and is RECOMPUTED by the verifier (a stored copy is never trusted).
**Mixed OPEN + CLOSED in ONE shard.** visibility is per-partition, so one derived shard MAY carry an OPEN
partition (sun position — plain value, anyone can independently recompute and compare) AND a CLOSED partition
(a proprietary BSI value — `privacy:"blinded"`) at once.

### 4.5 What a UST looks like — a complete annotated example
A minimal public **observation** Transcript (a space-weather reading). Note: every leaf is a STRING (§5),
partitions live under `data` (`space_weather` is the operator's schema name), and the whole `state` is
signed — nothing that carries meaning is outside `sig`.
```json
{
  "ust": "1.0",                                            // protocol marker — the document self-identifies FIRST
  "state": {
    "id":   { "domain_shard": "helioradar.com",          // who
              "ust_id":       "ust:20260424.15",          // which frame (hour tier)
              "key_id":       "sha256:40dc6b0d…7e5feb",     // which signing key (= H_keylog(pub))
              "class":        "observation" },
    "time": { "generated_at": "2026-04-24T15:03:12Z",      // asserted seal instant (signed; anchor is the real time)
              "valid_from":   "2026-04-24T15:00:00Z",
              "valid_to":     "2026-04-24T16:00:00Z" },
    "data": {                                           // partitions — each an envelope {kind, value}
      "space_weather": {
        "kind":  "captured",                               // captured → hash binds domain_shard (§4.4)
        "value": { "bz": "-2.82", "kp": "3.0", "solar_wind_density": "3.66",
                   "solar_wind_speed": "482.9", "xray_flux": "0.000001" }  // STRINGS, verbatim (§5)
      }
    },
    "hashes": { "space_weather": "sha256:0a79670517c3…5427d" }  // per-partition hash (recomputed by verifier)
  },
  "sig": { "alg": "Ed25519", "key_id": "sha256:40dc6b0d…7e5feb", "pub": "b64url(pubkey)",
           "sig": "base64url(EdDSA over canon({ust,state}))" }
}
```
A LIGHT verifier (the floor): recomputes `canon({ust,state})`, each `hashes.<p>`, and `content_hash`; strict-verifies
`sig` against the CARRIED `sig.pub`. That establishes **what bytes / which frame / which key signed** offline —
identity strength `self-asserted` (the `domain_shard` is authoritative only at HIGH, §12). **When** (anchored)
needs a `proof` (§11.2); **from what** needs `provenance` (§9). This one carries neither → time `unproven`,
name `self-asserted` — still a fully key-authentic, integrity-valid UST at LIGHT.

**Reproducible (the first conformance vector, keyed).** Full `key_id` = `sha256:40dc6b0dad81d8f5f17a9c3b93fd2b6b7090b0170ebcf77a3434ee93787e5feb`.
The per-partition hash `hashes.space_weather = H_shard(canon({domain_shard,ust_id,space_weather:value})) =
sha256:0a79670517c3f97c8a66db655f61c622f5a1cdbbdbded8073b23f08150b5427d`. The **signed content** `S = canon({ust,state})`
(§7 — the whole transcript minus `sig`/`proof`) is EXACTLY:
```
{"state":{"data":{"space_weather":{"kind":"captured","value":{"bz":"-2.82","kp":"3.0","solar_wind_density":"3.66","solar_wind_speed":"482.9","xray_flux":"0.000001"}}},"hashes":{"space_weather":"sha256:0a79670517c3f97c8a66db655f61c622f5a1cdbbdbded8073b23f08150b5427d"},"id":{"class":"observation","domain_shard":"helioradar.com","key_id":"sha256:40dc6b0dad81d8f5f17a9c3b93fd2b6b7090b0170ebcf77a3434ee93787e5feb","ust_id":"ust:20260424.15"},"time":{"generated_at":"2026-04-24T15:03:12Z","valid_from":"2026-04-24T15:00:00Z","valid_to":"2026-04-24T16:00:00Z"}},"ust":"1.0"}
```
The **content_hash** `= H_state(canon({ust,state}))` — the UNIQUE document descriptor (§7) —
= `sha256:2c9ced09fae6e729e55319b60d45975b5a53e382335bcf1e5846335970dff683`. A signed instance (Ed25519 seed
`0011…eeff`, `pub = PM0kHP_Js2GARLl9A22GFFk9iwF8NA8d7odzOFUXZUs`) + 8 more vectors (hash / sig-valid / sig-
tampered→E-SIG / canon-reject×3 / bounds) are in `vectors/conformance-vectors.json` — the normative suite (§16,
App. A). Any conforming implementation MUST reproduce these byte-for-byte.

---

## 5. Value model (uniform, string-only)

Every leaf value in `data` and `provenance` is a **UTF-8 string**. There are NO JSON numbers, no JSON
booleans, no JSON null as leaves.
- A captured measurement is the source's textual form, verbatim: `"59.82"`, never `59.82` (byte-preserving;
  no re-parsing that could reformat `4.290`→`4.29`).
- A boolean is `"true"`/`"false"`; an absent value is an absent key (never a null leaf).
- Structured meaning is expressed within strings (e.g. a unit-tagged value is `"degC:22.86"` by profile
  convention), never as a bare number.

Rationale (I4): JSON number formatting is language-dependent; forbidding number leaves makes the canonical
bytes identical across every implementation and removes the number/string equivocation class entirely.

---

## 6. Canonicalization

`canon(v)` produces the unique UTF-8 byte string for a JSON value `v`, per RFC 8785 (JCS) with the
following REQUIRED tightenings. A value violating any rule is malformed (E-CANON).

1. **Objects:** member names MUST be unique (duplicate ⇒ E-CANON). Names sorted ascending by UTF-16 code
   unit — FULL-LENGTH comparison (a name compares to its last unit at any admitted length; truncated
   comparison is non-conforming). Members joined `"name":value` with `,`; no whitespace anywhere. Members with absent values do not
   occur (§5).
2. **Strings** (names and leaves): MUST be Unicode NFC (non-NFC ⇒ E-CANON). Escaped per RFC 8259 §7 minimal
   escaping (control chars, `"`, `\`; no gratuitous escapes).
3. **Arrays:** `[` items in order joined by `,` `]`. Item order is significant and is part of the meaning.
4. **Leaves:** strings only (§5). Encountering a JSON number/boolean/null leaf ⇒ E-CANON.
5. **Depth/size:** within §13 bounds; exceeding ⇒ E-BOUNDS.

**Pinned value encodings (M9) — VALUE-MODEL conventions, NOT canon rules (ustate-finding).** `canon` is
FIELD-AGNOSTIC: it serializes strings faithfully and cannot know a string is a timestamp or binary, so these are
enforced where the field TYPE is known (§14 step 5 shape), not inside `canon`: timestamps MUST be RFC 3339 UTC
with a literal `Z`, no fractional seconds, no numeric offset, NO leap seconds (`:60`), and valid ranges only (month 01-12, day 01-31, hour 00-23, minute/second 00-59; publishers MUST smear leap seconds to `:59` so two conforming verifiers ALWAYS agree, I4) (e.g. `2026-07-04T08:06:30Z`) — any other form ⇒
**E-MALFORMED** (§14.5), not E-CANON; all binary values (nonces, signatures, ciphertext) MUST be unpadded
base64url. A producer MUST emit these forms; a verifier rejects a non-conforming timestamp at shape. (`canon`
itself is deterministic on any string — the encoding pinning removes cross-producer ambiguity, but the CHECK is
a shape check.)

`canon` is total and deterministic: same value ⇒ same bytes, on every conforming implementation (I4). The
conformance suite (§16) pins this byte-for-byte.

---

## 7. Content hash & signature

The **signed content** is `S = canon({ust, state})` — the whole transcript MINUS `sig` and `proof` (I1:
everything asserted — protocol version, identity, time, data, hashes, provenance — is inside the signature;
only the signature itself and the detachable time-`proof` are outside). The **content_hash** `= H_state(S)` is
the UNIQUE descriptor of this signed document: anchors (§11), chain references (`prev`/`constituents`/
`based_on`/`seed`, §9) and revocation (§12) all key on it, so two documents differing in ANY signed field
(signer, time, a data value) get DIFFERENT `content_hash`es — no anchor/chain aliasing. Domain-separation
tags are NUL-free ASCII, so the `0x00` separator makes tag boundaries unambiguous — registry growth cannot
create cross-tag collisions. Ed25519 verification is STRICT per RFC 8032 §5.1.7: a non-canonical `R`/`S`/`A`
encoding ⇒ E-SIG. (There is no
"cross-engine corroboration via an identical hash": the domain-less `computed` mode was REMOVED in rc.2 as
forgeable + fragile, §4.4. Every partition hash binds `domain_shard`; real corroboration compares two
publisher-bound values a layer up.)

- **Content hash (domain-separated, M6/P8):** every hash in UST is typed —
  `H_t(x) = "sha256:" || lowerhex( SHA-256( ascii(t) || 0x00 || x ) )`. **Exact byte layout (P8):** `ascii(t)`
  is the tag's literal ASCII bytes, then ONE `0x00` byte, then `x`, where `x` per tag is:
  `ust:state`→`utf8(canon({ust,state}))` (the signed content); `ust:keylog` has TWO byte-disjoint inputs — for a `key_id` it is the RAW public-key bytes (`key_id = H("ust:keylog", pub_raw)`, where `pub_raw` = the octets of the key, i.e. base64url-decode(`sig.pub`) — NOT plain `SHA256(pub)`, NOT the base64url string), and for a key-log ENTRY hash it is `utf8(canon(entry-without-sig))` (32 raw key bytes can never equal a JSON-object canon, so no collision); `ust:checkpoint`→
  `utf8(canon({ust,state}))` (a checkpoint is a transcript); `ust:leaf`→the leaf's `content_hash` ASCII bytes;
  `ust:node`→`left_hash_ascii || right_hash_ascii` (both `sha256:`-prefixed, concatenated); `ust:seed`→
  `utf8(canon([content_hash,…]))`; `ust:source`→the source bytes. Distinct tags make a bytes-equal collision across object kinds impossible. `content_hash = H_state(S)` where
  `S = canon({ust, state})` (the signed content) is the document's UNIQUE reference (chains §9, anchors §11,
  revocation §12); the PER-PARTITION hashes `H_shard(...)` in `state.hashes` (§4.4) are publisher-scoped (each
  binds `domain_shard`). Both are domain-separated; the vectors are normative (§16). `content_hash` is derived
  — a verifier recomputes it and MUST NOT trust a transmitted copy.
- **Signature (REQUIRED):**
  ```
  Signature := { "alg": "Ed25519", "key_id": string, "pub": b64url, "sig": base64url( Ed25519_sign(privkey, S) ) }
  //  pub — the signing public key, carried so LIGHT verification is self-contained; key_id = H_keylog(pub).
  //  At HIGH/TOP the key is ALSO resolvable via the key log (§12), which adds name authority.
  ```
  The signing input is EXACTLY `S = canon({ "ust": <top>, "state": State })` — the whole transcript MINUS `sig`
  and `proof` (I1: everything asserted, incl. the protocol version, is signed; only the signature and the
  detachable time-proof are outside), nothing more, nothing less. `Signature.key_id`
  MUST equal `State.id.key_id` (mismatch ⇒ E-SIG). **Ed25519 verification MUST be STRICT (N6):** per RFC 8032,
  reject a non-canonical scalar `S ≥ L`, reject small-order / non-canonical `A` and `R` encodings, and use
  cofactorless verification. "One algorithm" (I4) includes ONE acceptance rule — signature-malleability vectors
  are part of the conformance suite (§16), so no two verifiers can disagree on a signature. Because the key_id and domain_shard are inside the signed
  State, a signature cannot be re-attributed to a different key or publisher (I1/I2).

The State is signed WHOLE (I1): `sig` and `content_hash` share ONE preimage `S = canon({ust,state})`;
nothing meaningful is unsigned. Frame-level cross-engine matching is the per-partition hash job (§4.4), not the document hash.

---

## 8. Addressing — `ust:`

```
ust_id = "ust:" YYYYMMDD "." HH [ MM [ SS ] ]        (UTC; tiers: hour ⊃ minute ⊃ second)
```
The address is a time-frame, not an instant; tiers compose. Cadence within a tier is an operator choice
(§20). The precision **tier is derived from the `ust_id` string shape** — there is no separate precision
field to forge. Two transcripts denote the same frame iff they share BOTH `domain_shard` and `ust_id`. The protocol ALLOWS
multiple transcripts per frame (re-observations, corrections); UNIQUENESS of one authoritative document per
`(domain_shard, ust_id, tier)` is a COMPLETENESS property (§11.3), NOT a base guarantee — load-bearing against
commitment grinding (§10, Y1).

### 8.1 `parent_ust` (RESTORED — load-bearing for hour-close)
A finer-tier shard MAY name `id.parent_ust` = the coarser frame it refines (a second-precision shard → its
hour). It is navigation/lineage AND the anchor for **hour-close timing**: as an hour frame "closes," finer
shards keep arriving across the internet-lag boundary (the v0.27 grace); `parent_ust` links them to the hour so
a verifier assembles/closes the coarse frame correctly. **Hour-close at LIGHT/HIGH is HEURISTIC (timeout-based),
NOT a completeness guarantee:** a verifier can never be cryptographically certain the hour is "closed" — the
publisher may have skipped a tick, undetectable without a TOP sequenced-stream + anchor (§11.3). Consumers
(and MCP/clients) MUST NOT read a `parent_ust`-assembled hour as PROVEN-complete at HIGH; proven completeness is
a TOP property only. The hour-close timeout itself is an OPERATOR-PROFILE declaration (§20; RECOMMENDED default:
75 s past the frame boundary — the v0.27 ingest grace). It gates ASSEMBLY only and never enters any document's
verdict — two verifiers with different timeouts may assemble different provisional hours but can never disagree
on a document (I4). It is inside the signed content `canon({ust,state})`, so it is authentic AND part of the `content_hash` (§7 —
the document hash covers the whole signed content). It is navigation/lineage metadata (it does not affect any
PER-PARTITION hash, §4.4).

---

## 9. Provenance & chaining

`provenance` (OPTIONAL; present per `class`) is signed (inside the State, I1):
```
Provenance := {
  "sources":     { <source_id>: { "addr": content_hash, "src_sig": string } },   // OPTIONAL (§9.1)
  "constituents":[ content_hash, ... ],                                          // OPTIONAL (§9.2)
  "based_on":    [ { "hash": content_hash, "url": string } , ... ],              // OPTIONAL (§9.3)
  "root":        content_hash,                                                   // OPTIONAL (§9.2)
  "seed":        content_hash,                                                   // OPTIONAL (§9.4)
  "prev":        content_hash                                                    // present in a SEQUENCED stream (operator completeness guarantee, §11.3); else absent
}
```

### 9.1 Sources — bound identity (I8)
Each `<source_id>` maps to `{ addr, src_sig }` where `addr` content-addresses the exact source bytes and
`src_sig` binds the named source to `addr` — either the source's own signature over `addr`, or a membership
proof in a known-source registry resolvable like a publisher profile (§12/§20). A source entry lacking a
verifiable `src_sig` is an operator LABEL: a verifier MUST mark it UNAUTHENTICATED and MUST NOT surface it as
source attribution.

### 9.2 Constituents & root (attestation)
An attestation over N constituent records lists their `content_hash`es (bounded, §13) and MAY summarize them
with `root` = the RFC 6962 Merkle root over the constituent `content_hash`es **sorted byte-ascending on the
`content_hash` string (M8, the single pinned ordering)**, using domain-separated leaf/node hashing (`ust:leaf`
/ `ust:node`, §7). Two honest builders over the same set ALWAYS produce the same root. Because `provenance` is
inside the signed State, `root` is signed (closing the "signature binds nothing but a frame" gap): a valid
attestation binds its root, AND the root's un-backdatable time comes from the anchor (§11).

### 9.3 based_on — advisory lineage
`based_on[i].hash` is authoritative and content-addressed; `based_on[i].url` is ADVISORY only and MUST NOT be
a basis for any integrity decision (a URL may be swapped; a hash cannot). Referencing another record is a
**directional** claim by this State and does NOT implicate or endorse the referent (§18.2). **Symmetrically
(Y4): an INBOUND reference confers NOTHING — a consumer MUST NOT infer endorsement or association from a
reference it did not itself originate, and a referent cannot control who points at it (reference-spam is free).**

### 9.4 seed — order-bearing composite
`seed` = `H_seed( canon([ h_1, ..., h_k ]) )` (its own domain tag `ust:seed`, §7/§17) over the referenced `content_hash`es in the SAME pinned order as
`based_on`/`constituents` appear in the (signed) State — order is meaning and is fixed by the signed array,
not re-sorted (M8). Proves participation/order without inlining referents (useful with private constituents, §10).
`based_on`/`constituents` MUST NOT contain duplicate `content_hash`es — a duplicate is a shape error
(E-MALFORMED, §14 step 5): citing a referent twice has no composite meaning, and a duplicated constituent
double-counts a leaf in the Merkle root. Verifiers recompute the seed over the signed array VERBATIM either
way, so conforming verifiers cannot diverge on order or multiplicity — the rule pins admissibility, not math.
If a State carries BOTH `constituents`+`root` AND `based_on`+`seed`, each pair is verified INDEPENDENTLY —
`root` binds the constituents (E-ROOT), `seed` binds the based_on list (E-SEED); one never waives the other.

### 9.5 Chain walking (bounded, acyclic — I5)
Chain resolution is governed by the verification-depth model (§13): DEFAULT depth-0 leaves referents
present-but-unverified; a caller opting into depth-k verifies referents up to k hops (hard max 32), breadth
≤64 per node, with a visited-set keyed by `content_hash` (repeat ⇒ E-CYCLE). Chain resolution NEVER blocks
identity/integrity of the local State (§14 steps 1–5 complete regardless of referent availability).

---

## 10. Privacy — PER-PARTITION, three modes (029 layers + hardening)

Visibility is per-PARTITION (§4.4): a document mixes public and private partitions freely. Three modes,
WEAKEST → strongest (do NOT conflate — E5):
- **secret-URL — REMOVED as a privacy mode (rc.4).** Publishing a partition at a non-guessable URL is a
  DISCLOSURE CHANNEL (how an authorized party receives the plaintext, §out-of-scope G18), not a cryptographic
  privacy mode — a verifier checks nothing (obscurity only; a bearer secret in a URL leaks via Referer, logs,
  CDN, history, TLS SNI). The use-case is covered by a `blinded` commit in the signed state + URL delivery as one
  operator channel. `privacy` modes are `blinded` and `encrypted` only. This once-useful 029 idea is superseded;
  exposing the URL.
- **blinded (cryptographic)** — the partition's `value` is replaced by
  `commit = H_shard( canon({ domain_shard, ust_id, "nonce": <b64url ≥128-bit>, "partition": <name>, value }) )` — FRAME-BOUND
  like public partitions (G23: without `domain_shard`/`ust_id` the same commit is replayable into any other
  frame/publisher); the
  nonce MUST be FRESHLY RANDOM and UNIQUE per commitment (≥128 bit; never reused, never derived from the value —
  a repeated nonce makes two commits to the SAME value EQUAL, leaking value-repeats, Z2), disclosed only to
  authorized parties, who reproduce `commit`. Public parties get existence+time only and CANNOT brute-force
  low-entropy values (I6). (A verifier cannot detect cross-document nonce reuse — it is a producer MUST.)
- **encrypted (cryptographic)** — `commit` as for blinded, PLUS an authenticated-encryption block `enc` binding the ciphertext
  to the SAME plaintext: `ct` MUST be an AEAD encryption of exactly the `value` that `commit` commits to, under
  the key named by `enc.key_id`. A key-holder MUST verify `AEAD-Decrypt(ct)` reproduces the committed
  `{nonce,value}` → `commit` (E-COMMIT on mismatch); decryption and commitment can NEVER diverge. Ciphertext is
  NEVER anchored — only `content_hash`/`commit` are; raw bytes live in the erasable pack store, so erasure
  orphans the hash (takedown/erasure without breaking the anchor).

`enc.alg` MUST be an AEAD from the registry (§17): `XChaCha20-Poly1305` (RECOMMENDED — misuse-resistant nonce
size) or `AES-256-GCM` (permitted only with a stated unique-nonce-per-key derivation; GCM nonce reuse is
catastrophic). A MAC-less mode is invalid (E-MALFORMED). Obtaining/authenticating the `enc.key_id` decryption
key and its rotation is KEY MANAGEMENT — explicitly OUT OF PROTOCOL SCOPE; the protocol fixes only the AEAD
binding (§14 step 8) and the commitment.

**Disclosure channel (out of scope, G18):** HOW an authorized party receives `{nonce,value}` (for blinded) or
the decryption key (for encrypted) is the operator's concern, like `enc.key_id` key management — out of protocol
scope. The `commit` BINDS the disclosure: a wrong `{nonce,value}` cannot reproduce the commitment, so a bad
channel cannot forge, only fail to reveal.

**What is confirmed vs what is hidden.** UST confirms the FACT of a sealing — who/what-partitions/when/lineage;
whether the partition VALUES are public or hidden is the publisher's choice (blinded/encrypted, §10). By design
the record's existence, `ust_id`, `class`, and partition NAMES are part of the confirmed fact and are public;
hiding the DATA is on the publisher, and the publisher who also wants an opaque name simply names the partition
opaquely (a pseudonym, not `position`). The protocol does not claim to hide the fact of publication — that is
its job to confirm, not conceal.

**Metadata minimization (profile-declared, MAY):** a confidential publisher MAY additionally collapse
`provenance.sources` to a single opaque `root` and SHOULD pad ciphertext to a size bucket (powers-of-two; the profile declares its padding policy, §20 —
an unpadded ciphertext reveals plaintext length), to limit topology/size
leakage. Key management is out of scope; the protocol fixes only the commitment/blinding rules.

**Commitment ≠ pre-registration (Y1 — the grinding guard).** A REVEALED commitment proves only that THIS value
existed and was signed/anchored at that time — NEVER that it was the ONLY commitment for the frame. Since the
protocol allows multiple transcripts per `(domain_shard, ust_id)` (§8), a publisher can commit to N outcomes
and reveal only the winner (multi-commit grinding), fabricating a track record — the direct attack on a
prediction notary. A "pre-registered prediction" claim is verifiable ONLY inside a sequenced stream (§11.3)
that enforces ONE authoritative document per frame slot (a second ⇒ E-PREV fork). WITHOUT a verified-complete
stream (the range verdict, §11.3), a revealed commitment carries existence+time, NOT uniqueness or pre-registration.

---

## 10a. Shard chain & LAYERS — selective disclosure (029's richest feature, RESTORED)

A shard chain is a sequence of **layers**, each a normal signed UST document, that extend one another; a
**layer seed** commits to all layers at once, enabling selective disclosure.
```
L1 — public shard      (visible to everyone)
L2 — private shard     (blinded commitment, §10)
L3 — encrypted shard   (partition(s) encrypted, §10)
L4 — partner shard     (published by a third party holding the L3 key)
…   any layer public/private, encrypted/plaintext; the chain stops at any depth.
```
- **Layer seed (the §9.4 mechanism, no self-reference — G20):** the outer layer's
  `seed = H_seed( canon([ content_hash, … ]) )` over the CONTENT_HASHES of its SUBORDINATE layers (L2..Ln) in
  signed order — NOT its own canonical. So there is NO circular definition (the outer layer's own `content_hash`
  is computed AFTER, over a canon that already contains this seed). It commits to every subordinate layer;
  private layers PARTICIPATE without their URL appearing in any public field.
- **The two layer relationships have NAMES (they are different operations — do not conflate):**
  **`seals`** — the CONTAINING direction: an outer layer's `seed` commits to its subordinate layers (L1 seals
  L2..Ln). The bundle is pre-linked: publishing the outer layer proves the sealed set existed, but no layer can
  be added to it afterwards. **`extends`** (derives_from) — the APPEND direction: a NEW layer cites prior layers
  via `based_on` (+ recomputed `seed`, §9.4), under its own key (L4 extends L1..L3). Anyone holding the cited
  layers can extend; the older layers never vouch for the newer (no retroactive containment). A chain may use
  both: seal what you publish together, extend what grows later.
- **Third-party extension (the bootstrap mechanism):** a holder of the L3 key fetches L1..L3, builds
  L4, computes L4's seed over the content_hashes of L1..L3 (its subordinate layers, §9.4), and publishes L4 — chaining ACROSS publishers (e.g. noosphere +
  helioradar + muuune → a BSI derived shard extends the chain).
- **Layer availability:** an UNRESOLVABLE inner layer is an availability condition, not a failure — the outer
  layer's local verification (§14 steps 1–5) stands, and a depth-k walk reports `referents:"partial"` (§14.9);
  a missing layer is NEVER INVALID (availability ≠ failure).
- **Layer authenticity (E4):** the seed proves participation + integrity of the layer canonicals AS FETCHED —
  it does NOT transfer authenticity. Each held layer's AUTHENTICITY requires verifying THAT layer's own `sig`
  (I2). A verifier MUST verify each held layer independently; a malicious outer publisher can seed over forged
  inner canonicals, caught only by each inner layer's signature.
- **Per-party verification depth:** a party holding layers 1..N verifies 1..N; it cannot verify layers beyond
  what it holds.

---

## 11. Anchoring & time

### 11.1 Anchoring & honest gaps
An operator batches `content_hash`es → a Merkle `root` → commits `root` into a public append-only log
(the substrate is an operator choice, §17/§20 — noosphere uses git + OpenTimestamps/Bitcoin + IPFS as ONE
example; another operator MAY register a different public append-only log). Time semantics:
- **Un-backdatable time** for a State is obtained by resolving its `content_hash` to an anchored `root`
  whose append-only-log commitment fixes "not later than". The verifier's trust root is the LOG commitment,
  reached via the anchored key log (§12) — never a mutable repository mapping (I7).
- **On-time or honest gap:** retro-anchoring a hash under a past time is forgery and is fatal. A missing
  frame MUST be published as a **signed gap record** — `class:"attestation"` with `provenance.prev` set (it is
  a normal frame in the stream) but EMPTY `constituents` and a data partition asserting the gap; this is the
  one attestation whose `constituents` may be empty (§14 step 5) — so that sustained gaps are provably honest, not
  indistinguishable from compromise.
- **Signed timing is an ASSERTION, upper-bounded only (N9).** The anchor guarantees "not later than" its log
  commitment; NOTHING bounds "not earlier than". `generated_at`/`valid_*` are signed but publisher-asserted;
  a verifier MUST derive freshness/ordering from the ANCHOR, treat `generated_at` as advisory-though-signed,
  and MUST reject `generated_at` later than the anchor time with E-ANCHOR (no future-sealing the anchor contradicts).
- Only hashes are anchored, never raw or ciphertext data.

### 11.2 Self-contained time — the anchor proof (I12, N4)
Anchored time MUST NOT depend on a mutable lookup. A verifier obtains time from an **AnchorProof** carried in
the transcript (or supplied by the caller):
```
AnchorProof := { "root": ContentHash, "path": [ {"dir":"L"|"R","hash":ContentHash}, ... ], "anchor": Locator }
```
The verifier recomputes the Merkle path from the State's `content_hash` to `root` (RFC 6962, domain-separated
leaves/nodes per §7), then validates `root`'s commitment under the **substrate's verification profile**:
```
Locator := { "substrate": string, ... }   // substrate ∈ the anchor-substrate registry (§17); remaining
                                          // fields are that substrate's evidence (see its registry entry)
```
**The anchor SUBSTRATE is an operator choice (like the signature scheme), NOT the protocol.** The protocol
fixes only: (1) the proof is self-contained/in-band (the inclusion path above — no mutable lookup, I12); (2)
`root` MUST be committed to a PUBLIC append-only log; (3) the substrate MUST be a REGISTERED substrate (§17)
whose verification procedure is deterministic, and the operator MUST declare which one (§20). A verifier loads
that substrate's verification profile (its evidence format, its "public append-only log" check, its minimum
confirmation/finality parameter) and applies it; an unregistered or unverifiable substrate ⇒ time = UNPROVEN.
A **not-yet-final** commitment (per the substrate's finality rule) yields UNPROVEN, NEVER `VALID`-time. No
operator index or mutable API is consulted for the mapping — the proof IS the mapping (I12). Absent a final
proof, identity/integrity still verify but time is UNPROVEN (fail-closed per §14 step 6). Each registered
substrate ships normative vectors (§16). (noosphere registers/uses `bitcoin-ots` — OTS→Bitcoin header, ≥6
confirmations — in its operator profile; that is one substrate, not the protocol.)

### 11.3 Sequence completeness — an operator GUARANTEE (I11, N5, M4, M5)
Completeness (no silent omission of frames) is a NOTARY-grade **operator guarantee**, NOT a protocol
requirement for a basic record — the same layer as anchoring. An operator that offers it declares a
**sequenced stream** in its profile (§20); a verifier reports the completeness STRENGTH reached (proven /
provisional / none), it is not a gate unless the consumer requires completeness.

Within a declared sequenced stream, each frame's State carries a signed `provenance.prev` = the
`content_hash` of the publisher's immediately-preceding frame for the same `(domain_shard, tier)` — a
hash-linked stream. A withheld frame leaves the next frame's `prev` dangling ⇒ E-PREV (for consumers checking
completeness). A one-off State outside any sequenced stream has no `prev` and is complete-strength `none` —
still fully identity+integrity verifiable.

**Completeness ≠ validity (X2).** The `prev`-chain proves LINKAGE (hash continuity), NOT that every frame is
individually VALID: a stream can be link-complete while a frame inside it is signed by a since-compromised key
(§12.2). A consumer requiring completeness MUST ALSO verify EACH frame per §14 (signature + revocation at that
frame's anchored time); completeness strength and per-frame validity are COMBINED, never conflated into "the
stream is complete, therefore trusted."

**Stream genesis (M4).** The FIRST frame of a stream sets `prev` = the publisher's **genesis `content_hash`**
(§12.1), binding the stream's origin to the identity root. A stream has exactly ONE genesis-anchored origin per
`(domain_shard, tier)`; a second frame claiming first-position (a `prev` = genesis when an origin already
exists) ⇒ E-PREV. This forecloses "orphan a new stream to hide prior frames."

**Frame-slot uniqueness (Y1).** Within a sequenced stream the `prev`-chain is LINEAR: exactly ONE authoritative
document per `(domain_shard, ust_id, tier)`; a second document for an occupied slot is a fork ⇒ E-PREV
(checkpoint-detected). This is precisely what makes a committed prediction NON-grindable (§10) — and it holds
ONLY when the stream is verified complete (the range verdict, §11.3); one-off documents carry no slot-uniqueness.

**Checkpoints (M5).** Checkpoints are themselves `prev`-chained frames (`class:"attestation"`) that assert the
stream head + frame count over an interval. The asserted `frame_count` is CUMULATIVE from the stream origin, so
a later covering checkpoint proves every earlier interval transitively — a missing intermediate checkpoint
delays proof but cannot hide frames (an absent frame breaks `prev`). The operator profile declares a REQUIRED checkpoint cadence; a
consumer requiring completeness MUST have a covering checkpoint whose asserted head hash-links to the frames it
sees — a missing or contradicting checkpoint ⇒ E-PREV (fail closed).

**Completeness scope (P5).** Completeness is PROVEN only for CLOSED intervals (those with a covering
checkpoint). The open tail after the last checkpoint is provable only up to `head`; the profile declares a
MAXIMUM checkpoint LAG, so the unprovable tail is bounded in time and a consumer treats post-last-checkpoint
frames as PROVISIONAL. Withholding a checkpoint past the max lag is itself a detectable violation. The range VERDICT consumes ONLY
signed inputs (the frames + the covering checkpoint); declared cadence/max-lag are accountability expectations
for consumers — a profile change can never change any verdict (I4).

**Cross-tier & resumption (P6).** Each declared tier `(domain_shard, tier)` has its own `prev` stream; the
SET of tiers a publisher runs is declared in the profile, so a silently-absent tier is detectable against the
declaration. Resumption after an outage MUST be a CONTINUATION (`prev` = last pre-outage frame) with an
intervening signed gap record — NEVER a new stream-genesis (which is reserved for the true first-ever origin,
M4); a resumed stream re-claiming genesis ⇒ E-PREV.

---

## 12. Identity & key transparency (I2/I7/I11)

### 12.1 Genesis authority — binding `domain_shard` to a key log (N1) — HIGH/TOP tier
Genesis/key-log is the HIGH/TOP mechanism that makes a `domain_shard` NAME authoritative; the LIGHT floor does
NOT require it (a floor document is key-authenticated with a self-asserted name, §3.1). The genesis is itself a
UST transcript with `state.id.class = "genesis"`, SELF-SIGNED by the genesis key (the base case of the key log,
§12.2), whose `state.data.genesis.value` carries the genesis `pub` and `role:"name-binding-root"` — one wire
shape even for the root of trust; it is verified by §14 like any document. The value MAY carry
`max_partitions` (a string integer, 1..4096): the publisher's DECLARED partition capacity for documents under
this `domain_shard` — the §13 ladder admits above-floor documents against it; absent ⇒ the 64 floor applies.
The value MAY likewise carry `max_transcript_bytes` (a string integer, 1..67108864): the declared transcript
size capacity — same ladder, same rules, floor 1 MiB (§13).
The declaration is signed and ceremony-rooted; it becomes usable capacity ONLY as a TRUSTED GRANT — the
output of authority resolution (`resolveAuthority` returns the declared `capacity`) or the caller's explicit
pin/policy, passed to verification as the grant. A document can never expand its own budget, and a raw
caller-attached genesis is NOT a grant (rc.12): a self-signed genesis would be a self-issued budget.
Anchoring is permissionless (anyone can commit any bytes), so "an anchored key log for noosphere.md" does NOT
by itself confer authority over the NAME — an attacker could anchor a rival log, even earlier. The **authoritative** genesis MUST be established by a NAME-BINDING root, one of (profile declares which):
1. **DNSSEC-bound genesis** — the genesis key's `content_hash` in a DNSSEC-signed record for `domain_shard`;
   the DNS chain of trust binds the NAME to the key. (Preferred.)
2. **TLS-ceremony genesis** — a one-time, signed genesis served over TLS at
   `https://<domain_shard>/.well-known/ust-genesis` and PINNED thereafter. TLS is used ONLY to bind genesis —
   a tiny, one-time trust surface — never per document.
The standard DNS record shape for (1) — and the corroboration record for (2) — is `_ust.<domain_shard>`
TXT `ust-genesis=<content_hash>`; the SERVING contract for both discovery surfaces (immutability,
query-robustness, mirrors) is §20.1 — operational, and per §1 never a verification input.
A **transparency-log witness (M2)** — the genesis gossiped to an independent CT-style log so a second genesis
for the same name is a publicly visible conflict — is REQUIRED as CORROBORATION but is NEVER the sole root
(TOFU alone loses the first-contact race). A verifier MUST resolve authority to a name-binding genesis (1 or 2)
AND POSITIVELY confirm via the witness that NO conflicting genesis exists before granting `authoritative`. A
FORKED genesis (a rival name-binding root exists) ⇒ `conflict` ⇒ E-GENESIS; an UNREACHABLE genesis/witness ⇒
`unavailable` (INDETERMINATE, §15), NOT E-GENESIS — and `authoritative` is DENIED, never silently granted (W1:
suppress-the-witness cannot mask a hijack — the attacker denies the strength but cannot forge it; an out-of-band
PINNED key is unaffected). **Genesis recovery — re-rooted in domain control (P2).** The ultimate authority is the NAME-BINDING root
(DNSSEC record / TLS-ceremony at the domain), NOT possession of the genesis KEY — the key log lives UNDER it.
A supersession is authoritative iff it is BOTH (a) signed by the old genesis key AND (b) reflected in the
CURRENT name-binding root (which only the true domain controller can change). This solves recovery-from-
compromise: a stolen genesis key ALONE cannot capture the name (it can't change the DNSSEC/TLS root), and the
true owner recovers by publishing a new genesis in the name-binding root. A supersession missing either half
is ignored; conflicting name-binding roots ⇒ E-GENESIS. Historical records stay valid under the genesis that
was authoritative at their anchored time (bounding domain-lapse / re-registration, P3). **(X3 — placing a
record in the correct genesis EPOCH requires its ANCHORED time; an UNANCHORED record signed by an old-genesis
key near/after a recovery cannot be epoch-placed and is rejected at HIGH, fail-closed. So across a recovery
boundary anchoring is EFFECTIVELY REQUIRED for HIGH validation.)** Anchor time/order is
necessary but NOT sufficient for name authority; domain control is the arbiter.

### 12.1a Witness log — the serving shape & the verifier auto-query (M2 made mechanical)

§12.1 fixes the SEMANTICS (positive no-fork confirmation REQUIRED for `authoritative`; fork ⇒ E-GENESIS;
unreachable ⇒ `unavailable`, W1). This section fixes the WIRE SHAPE a publisher serves and the QUERY a
verifier runs, so no-fork stops being a manual assertion and becomes COLLECTED EVIDENCE — zero manual steps.

**Serving shape.** A publisher claiming witness conformance serves, at
`https://<domain_shard>/.well-known/ust-witness`:
```
WitnessLog := { "domain_shard": string,            // MUST equal the serving name
                "active":       content_hash,      // the publisher's view of the current genesis
                "genesis_log":  [ { "content_hash": content_hash,      // of a genesis transcript (§12.1)
                                    ["superseded_by": content_hash,]   // §12.1 recovery/supersession
                                    "anchors": [ AnchorProof, … ] } ] }
```
`AnchorProof` is EXACTLY the §11.2 shape (`{root, path, anchor}`, substrate per the §17 registry; for a
single-genesis leaf, `root = H("ust:leaf", content_hash)` and `path = []`) — one verification path, no new
mechanism. The log is APPEND-ONLY: an existing entry's `content_hash`/`anchors` bytes never mutate (anchors
MAY be appended); supersession is expressed by ADDING `superseded_by` and a successor entry, never by removal.

**The endpoint is an INDEX, never an authority.** Every anchor is cross-checked against its substrate's
verification profile (§11.2 inclusion + §17 finality) — the substrate, not the endpoint, is the independent
truth. A log therefore CANNOT forge no-fork: omitting a rival genesis that is anchored on a public substrate
does not un-anchor it (the same claim ≠ proof rule as discovery mirrors, §20.1), and an unanchored entry
carries no weight. Self-published-but-externally-anchored sits strictly between self-attestation (weaker) and
an independent witness NETWORK (stronger; gossip/co-signed logs are an operator evolution, out of scope here).

**Verifier auto-query (normative, fail-closed).** After resolving authority (§12.2 walk), a verifier
collecting witness evidence MUST decide as follows. Let ACTIVE = entries without `superseded_by`; an entry
is ANCHORED iff at least one of its anchors passes BOTH the §11.2 inclusion check AND its substrate's
finality check (§17). A substrate the verifier does not implement contributes NOTHING (never a pass, never
a failure — `INDETERMINATE(unsupported)` discipline, §17):
- EXACTLY ONE anchored active entry, and it equals the resolved genesis ⇒ **positive no-fork confirmation**
  (§12.1 M2 satisfied) — `authoritative` MAY be granted.
- TWO OR MORE anchored active entries — or one that DIFFERS from the resolved genesis ⇒ a rival
  name-binding root is visible ⇒ `conflict` ⇒ **E-GENESIS** (a failure, not unavailability).
- ZERO anchored active entries (endpoint unreachable, log malformed, no anchor verifiable here) ⇒
  `unavailable` ⇒ `authoritative` is DENIED and the LIGHT floor stands (INDETERMINATE discipline, §15) —
  reported explicitly (e.g. "HIGH pending witness"), NEVER silently dropped, NEVER guessed (W1).
An explicit out-of-band caller assertion of no-fork MAY substitute for the query (air-gapped verification);
it MUST be reported as caller-asserted, distinguishable from collected evidence.

### 12.2 Key log — a genesis-rooted, self-signed chain (M1)
- A publisher's key log is a **sequenced stream (§11.3) of UST transcripts** — the SAME `{ust, state, sig,
  proof}` shape as any document (nothing changes across tier OR role, §16). Each entry is a transcript with
  `state.id.class = "key"`, carrying the operation in its data and the chain link in its provenance:
  ```
  state.data.key_op.value = { "op":"add"|"rotate"|"revoke", "pub":b64url,
                              ["reason":"retired"|"compromised", "compromised_since":RFC3339-Z — STRICT `YYYY-MM-DDTHH:MM:SSZ`; an offset or fractional form ⇒ E-MALFORMED (lexicographic comparison is then chronologically correct)] }
  state.provenance.prev   = <content_hash of the previous entry>   // first entry's prev = genesis content_hash (§12.1)
  ```
  The added key's identifier `key_id` = `H("ust:keylog", pub_raw)` where `pub_raw` = the RAW public-key octets
  (base64url-decode of `pub`), domain-separated (§7) — NOT plain `SHA256(pub)`, NOT the base64url string;
  content-derived, unique by construction (P9), reproduced byte-for-byte by the verifier (§14 step 4). **Each
  entry transcript MUST be signed by the CURRENT valid key**; the genesis key signs the first; each rotation is
  authorized by the key it supersedes; `revoke` requires the current or genesis key (profile MAY require a
  quorum). This forecloses M1. Because an entry is a normal transcript, it is verified by the SAME algorithm
  (§14) as any UST — the trust layer is built from the protocol's own documents.
  **Revocation semantics (P1) — decided against the anchor UPPER BOUND (X1).** The anchor gives ONLY an upper
  bound `U` ("not later than", N9); there is no lower bound, so validity is decided against `U`, fail-closed —
  you can prove a signature is BEFORE a threshold, never AFTER it:
  - `reason:"retired"` (hygienic rotation): a K-signed State is VALID iff its anchor `U ≤` the revocation's
    anchor time (its latest possible time is at/before rotation); otherwise EXPIRED.
  - `reason:"compromised"` + `compromised_since` C: a K-signed State is VALID **only if `U < C`** — its LATEST
    possible time is PROVABLY before the compromise. Since C is the publisher's own ESTIMATE (a thief may have
    held the key before C), such a State is VALID-but-**SUSPECT**. If **`U ≥ C`, OR the State is UNANCHORED**
    ⇒ **INVALID** (fail-closed: an upper bound `≥ C` cannot prove the signature predates the compromise). This
    is what actually stops a back-dating thief — he cannot obtain an anchor upper-bound EARLIER than reality.
- A verifier resolves `State.id.key_id` by walking this genesis-rooted chain (bounded ≤256 entries, §13) and
  taking the key valid at the State's anchored time; a BROKEN entry chain or an entry not signed by the
  then-current key ⇒ E-KEY (a failure); a FORKED genesis ⇒ E-GENESIS; an UNREACHABLE key-log/genesis ⇒
  INDETERMINATE (`unavailable`), NOT a failure (W1, §14 step 3/4 — availability ≠ failure). The `.well-known/ust` profile (§20) MAY serve as a cache but
  MUST be corroborated against the anchored key log for any acceptance decision (I7 — a poisoned `.well-known`
  or DNS cannot forge identity).
- TLS of the fetch path is NOT an identity input (I2). At LIGHT a document is KEY-authenticated by its carried
  `sig.pub`; at HIGH/TOP the key is resolved via this genesis-rooted log, which ALSO makes the `domain_shard`
  NAME authoritative. (§3.1 tiers.)
- **LIGHT has NO revocation (X4).** Revocation lives in the key log, which LIGHT does not consult — a
  `self-asserted`/`pinned` verification NEVER sees a revocation, so a compromised key keeps verifying at LIGHT.
  A consumer needing revocation (or name authority) MUST verify at HIGH/TOP. This is inherent to a carried/pinned
  (TOFU) key.

---

## 13. Structural bounds (I5) — hard ceilings

A verifier MUST reject (E-BOUNDS) any transcript exceeding, and a producer MUST NOT emit beyond:
| bound | ceiling |
|---|---|
| State nesting depth | 8 |
| total Transcript size | 1 MiB anonymous floor · genesis-declared ≤ 64 MiB (name-form, §12.1) · ABS 64 MiB |
| array length | 4096 |
| partitions per data | 64 anonymous floor · genesis-declared ≤ 4096 (name-form, §12.1) · ABS 4096 |
| `based_on`/`constituents` breadth per node | 64 |
| per-call walk depth (chain resolution) | 32 |
| ciphertext size | operator-declared, ≤ profile ceiling |
Cycle detection in chain walks is REQUIRED (§9.5). **Aggregate verification budget (P4):** full verification
of one State can fan out (key-log + genesis + anchor + each referent's own key-log/anchor/...). The verification-depth model: **DEFAULT depth-0** — the local State is fully verified; referents are present
but UNVERIFIED (the chain is not walked). **Depth-k** (caller opt-in) — referents verified up to k hops (hard
max 32, §9.5), under a caller-supplied budget of max fully-verified nodes and max external fetches; exceeding
either ⇒ fail-closed (E-BOUNDS): the reference default is 256 VERIFIED nodes (`refBudget`), and exhaustion
fails the WHOLE walk — never a partial success — so traversal order cannot affect any verdict (I4). This
forecloses fan-out DoS. **External-resolution bounds (N8):** key-log walk ≤ 256
events per resolution (use checkpointed heads + caching); anchor lookups are eliminated by the carried
inclusion proof (§11.2). A verifier MUST fail closed with E-BOUNDS on exceeding a resolution bound (the same
code as every §13 ceiling) — the resolution graph cannot be used to DoS verification. The key-log ceiling is
reached by rotation history, not truncation: past 256 entries resolution fails E-BOUNDS and the publisher's
escape is a NEW genesis epoch (§12.1 re-rooting) — a key log never truncates. **Bulk-verification note:** every
recomputed hash is a pure function of bytes — a verifier MAY cache per-partition and content hashes keyed by
`content_hash` across documents without affecting conformance (I4: same inputs, same verdict). Bounds are
conformance items (§16). **Partition-capacity ladder (rc.10 — bounds earned by ceremony):** ≤ 64 partitions is
the ANONYMOUS FLOOR — admissible for everyone, no context needed (LIGHT-anywhere is the mass case and stays
untouched). Above the floor, capacity is DECLARED BY THE CEREMONY: a name-form publisher whose genesis carries
`max_partitions` (§12.1) is admitted up to that declaration, hard-capped by the unconditional ABS ceiling of
4096 (the same number family as the array bound; a 1 MiB transcript physically holds ~8k minimal partitions, so
4096 is the structural sanity line, rejected at step 1). A KEY-FORM identity can hold no ceremony — the floor is
its law (E-BOUNDS). A name-form document above the floor verified WITHOUT its capacity-bearing genesis is
**INDETERMINATE (`unavailable`)** — the violation is unprovable and the floor unpassable, so the verdict ladder
is honest: INDETERMINATE → VALID as the genesis context arrives, never VALID → INVALID across tiers (I4: the
verdict is a total function of the document plus the supplied information set). The check runs at the §14
shape step, where the identity FORM is known. A tooling DEFAULT for `max_partitions` is a suggestion, never a
ceiling. **The SAME ladder governs transcript SIZE (rc.11/rc.12):** the NORMATIVE size metric is the UTF-8
byte length of the canonical SIGNED CONTENT `canon({ust, state})` — the exact string every verifier already
computes for the hash, so the measurement is free and transport formatting (whitespace, base64 wrapping) can
NEVER flip a verdict. The 1 MiB floor is the portable general-purpose floor for standard software verifiers and
ordinary message/file transport (NOT "fits in any context" — encodings and context economics vary); closed
corporate HIGH/TOP networks expand it by ceremony via `max_transcript_bytes` (§12.1), ABS 64 MiB — the maximum
size of a protocol OBJECT, not a mandatory memory capability of every verifier. **Three independent ceilings
(rc.12):** the protocol ABS (exceed ⇒ E-BOUNDS) · the publisher's TRUSTED GRANT (exceed ⇒ E-BOUNDS; absent
above the floor ⇒ INDETERMINATE `unavailable`) · the VERIFIER's own capability (protocol-valid but beyond this
implementation ⇒ INDETERMINATE `resource_limit`, never INVALID). TRANSPORT ADMISSION is separate from all
three: an implementation MAY refuse an over-budget raw input before decoding (measured on bytes, before any
materialization) as INDETERMINATE `resource_limit` — a refusal to start, never a verdict about the document.
Capacity is a TRUSTED GRANT, not a caller-attached genesis: the grant flows FROM authority resolution
(`resolveAuthority` surfaces the ceremony's declarations) or from the caller's pin/policy — a self-signed
genesis is a self-issued budget and expands nothing. Bulk beyond the ABS belongs OUTSIDE the transcript — a
State carries state and COMMITMENTS, never blobs: content-address the payload and reference it (§9.1 sources /
`source_anchors`). **§13 classification:** VOLUME bounds (partitions, canonical transcript bytes, ciphertext
bytes — a per-partition ciphertext cap keeps one encrypted shard from consuming the whole budget) scale with a
publisher's legitimate data and are ceremony-declarable — floor / declared / ABS; STRUCTURE bounds (nesting
depth, array length, breadth, per-call walk depth, key-log length) protect EVERY verifier's implementation
regardless of trust and are absolute laws — their escapes are structural: chunking, attestation TREES
(64² = 4096 in two levels), re-genesis epochs — never declarations. The DERIVATION of this law (volume vs structure as extensive vs
control-structure metrics), the capacity algebra, and the calibration doctrine for the concrete numbers live in
the formal model (F.9): *the model derives the law; benchmarks calibrate the constants.*

---

## 14. Verification algorithm (normative, ordered, fail-closed — I10)

Input: a Transcript `X`. Output: `VALID` with an attestation record, or a single specific error (§15).
The verifier MUST execute steps in order and MUST fail closed: any exception, timeout, resource limit, or
unresolved dependency ⇒ the corresponding error (never `VALID`).

1. **Structural admission.** Parse `X`. Require top-level `X.ust` (="1.0"), `X.state`, and `X.sig`. Reject unknown/duplicate reserved
   keys; verify namespace isolation (§4.2) and value model (§5) and bounds (§13). On failure → E-MALFORMED /
   E-CANON / E-BOUNDS. Unknown top-level members (other than `state`/`sig`/`proof`) are REJECTED — E-MALFORMED, fail-closed (no unsigned surface next to a VALID verdict; there is no `view`, N3).
2. **Canonical & hashes.** Compute the signed content `S = canon({ust, state})`, `content_hash = H_state(S)`.
   The `hashes` map MUST be an EXACT bijection with `data` (`hashes.keys == data.keys`; a missing OR extra entry
   ⇒ E-MALFORMED — G19: no partition may dodge its per-partition hash). Recompute each `hashes.<p>` (§4.4); a
   stored hash differing from the recomputed one ⇒ E-CANON; a failure to canonicalize ⇒ E-CANON.
3. **Name authority (TIER — NOT a floor gate).** The LIGHT floor does NOT resolve genesis. The verifier reports
   an identity STRENGTH (`self-asserted` | `pinned` | `authoritative`) WITH a STATUS (`verified` | `unavailable`
   | `conflict`) — AVAILABILITY is distinct from FAILURE (§15):
   - resolved to a name-binding genesis (§12) AND POSITIVELY confirmed via the witness that NO conflicting
     genesis exists → `authoritative`/`verified`;
   - a FORKED / conflicting name-binding root (a rival genesis EXISTS) → `conflict` ⇒ **E-GENESIS** (a real,
     deterministic failure);
   - genesis/witness UNREACHABLE (no mirror or anchor answered) → `unavailable` ⇒ **INDETERMINATE**, NOT a
     failure — retry; the document keeps whatever the LIGHT floor determined. Because the positive no-fork check
     could NOT complete, `authoritative` is DENIED here, NEVER silently granted (W1 — this forecloses
     suppress-the-witness-to-mask-a-name-binding-root hijack: an attacker can DENY the name-authority strength
     but cannot FORGE it; a consumer holding an out-of-band PINNED key is unaffected).
   A consumer that REQUIRES `authoritative` treats `conflict` as reject (E-GENESIS) and `unavailable` as
   retry/degraded — NEVER conflating "forged" with "couldn't reach the authority." Anchor time/order alone
   never confers name authority.
4. **Authenticity (MUST — the floor).** Require `X.sig.key_id == X.state.id.key_id == H_keylog(X.sig.pub)`.
   Obtain the public key: at LIGHT from the CARRIED `X.sig.pub`; at HIGH/TOP by resolving it via the
   genesis-rooted key log (§12, which also establishes name authority, step 3). STRICT-verify
   `Ed25519_verify(pub, S, X.sig.sig)` (§7, S = canon({ust,state})); failure ⇒ E-SIG; a key-log entry that BREAKS the chain or is unauthorized ⇒ E-KEY (a failure); an UNREACHABLE key-log ⇒ INDETERMINATE (`unavailable`), NOT E-KEY.
   The signature is ALWAYS verified (floor); only the KEY RESOLUTION is tiered. After this step every field of
   the State is authenticated (I1).
5. **Well-formed identity/time/shape.** Validate `ust_id` shape (§8), RFC 3339 times, `valid_from ≤ valid_to`,
   `class` in registry (§17) AND appropriate for the verification CONTEXT (W3: a key-log walk accepts ONLY `class:"key"`/`"genesis"`; a data/observation verify MUST NOT accept a `class:"key"`/`"genesis"` transcript as data, and vice-versa — a class-mismatch for the role ⇒ E-MALFORMED); ≥1 partition; each private partition (§4.4) carries a valid `commit` (+ `enc` if encrypted), and
   class↔provenance consistency (`derivation`/`attestation` REQUIRE `provenance`; `observation` MUST NOT
   carry `constituents`/`root`) (N10). SEMANTIC consistency is part of shape: every date MUST exist on the REAL
   calendar (range-valid strings like `Feb 31` are NOT dates — regex ranges alone are insufficient); a key-form
   `domain_shard` MUST equal `key_id` (§4.3a). On failure ⇒ E-MALFORMED.
6. **Time (self-contained, I12).** If `X.proof` is present, recompute the Merkle path from `content_hash` to
   `proof.root` and confirm `proof.root` at `proof.anchor` against the append-only log the verifier already
   trusts (§11.2); a proof that is PRESENT-but-WRONG (bad path/commitment) ⇒ E-ANCHOR (a failure). A MISSING,
   not-yet-final, or UNREACHABLE proof → time strength `unproven`/`unavailable` (INDETERMINATE); if the consumer
   REQUIRES anchored time this is a retry/degraded outcome, reserving E-ANCHOR for a proof that is present-but-wrong. `generated_at` MUST NOT exceed the anchor time (N9); real time is the anchor.
7. **Sequence (N5) — completeness STRENGTH.** If the operator declares a sequenced stream and the consumer
   requires completeness: `provenance.prev` MUST link the prior frame's `content_hash`; a dangling/rewound
   `prev` or a checkpoint (§11.3) contradicting the observed set ⇒ E-PREV. Otherwise this step yields a
   completeness STRENGTH (proven / provisional / none), not a gate. A one-off or completeness-not-required
   verification passes with completeness `none`/`provisional`.
8. **Privacy.** For each PRIVATE partition (blinded/encrypted, §4.4/§10), if authorized: reproduce its `commit`
   from the disclosed `{nonce,value}` + the document's `domain_shard`/`ust_id` (frame-bound, G23), and for `encrypted` verify `AEAD-Decrypt(enc.ct)` reproduces exactly that
   `{nonce,value}` → `commit` (E-COMMIT on mismatch). (A non-guessable delivery URL is an out-of-band channel, not a verified mode.) The
   layer seed (§9.5/§10a). Never brute-force.
9. **Provenance — the OBLIGATIONS TABLE (§14a).** Every commitment-bearing provenance member carries a
   RECOMPUTE obligation; a member may never be present-but-unchecked (the checked-root/unchecked-seed asymmetry
   class is abolished):

   | member | shape obligation | recompute obligation | on mismatch |
   |---|---|---|---|
   | `hashes.<p>` | — | per-partition hash (§4.4) | `E-CANON` |
   | `provenance.root` | `sha256:<hex64>` | `merkleRoot(constituents)` (§9.2) | `E-ROOT` |
   | `provenance.seed` | `sha256:<hex64>` | `H(ust:seed, canon(based_on[].hash))` (§9.4) | `E-SEED` |
   | `provenance.constituents[]` | each `sha256:<hex64>` | (referent walk, below) | `E-MALFORMED` |
   | `provenance.based_on[].hash` | `sha256:<hex64>` | (referent walk, below) | `E-MALFORMED` |
   | `provenance.prev` | `sha256:<hex64>` | chain link (§11.3, when a stream is verified) | `E-PREV` |
   | `commit` (private) | `sha256:<hex64>` | reproduce from disclosure (§10) | `E-COMMIT` |

   For each source verify `src_sig` (§9.1); unauthenticated ⇒ mark, never attribute. REFERENT WALK: depth-0 is
   the default (I14); the RESULT always reports how deep verification went (`provenance.depth`,
   `provenance.referents: "none" | "unverified" | "partial" | "verified"`) — a consumer can see the chain was
   NOT walked instead of assuming it was. With a caller-supplied resolver and a depth budget the verifier walks
   `based_on`/`constituents` bounded + acyclic (visited set ⇒ `E-CYCLE`; §13 bounds ⇒ `E-BOUNDS`); an
   unresolvable referent yields `referents:"partial"` (availability ≠ failure); a resolved referent that fails
   verification, or a resolver returning a document whose `content_hash` differs from the requested hash, is a
   REAL failure. **`referents:"verified"` asserts integrity, signatures and hash identity of the referenced
   documents — NEVER the semantic truth of their claims, and NEVER the correctness of a declared derivation
   function (a derivation may honestly cite its inputs and still compute nonsense; that is fixation, not
   truth, applied to lineage).** `url`s advisory only.
10. **Result.** `VALID` REQUIRES the FLOOR terminal checks: steps 1,2 (structure/canon), 4 (authenticity — the signature),
   5 (shape), 8 (per-partition private commitments when present), 9 (provenance when present). Step 3 (name
   authority) rejects (E-GENESIS) ONLY if the consumer requires `authoritative`; else it is a STRENGTH. Step 7
   (sequence) is a STRENGTH unless completeness is required. Any of these failing
   returns its error (§15) — NOT `VALID`. Step 6 (time) is a STRENGTH level, not a gate, UNLESS the consumer
   requires anchored time (then a missing/invalid proof ⇒ E-ANCHOR). A `VALID` result carries: publisher,
   ust_id, class, content_hash, the TIME strength (anchored / unproven, step 6), and the PROVENANCE/COMPLETENESS
   strength reached (step 9 / depth, §13), and an EXPLICIT `completeness` field — for a single-document verify
   always `"not_evaluated"` (completeness is a RANGE property, §11.3/§15; the field exists precisely so that
   `VALID:TOP` cannot be read as "all possible properties verified") — each STRENGTH paired with a STATUS (`verified`/`unavailable`/`conflict`,
   §15): an UNAVAILABLE higher-tier dependency yields INDETERMINATE-at-that-tier, NEVER INVALID. **The attestation asserts origin/integrity/time/lineage ONLY —
   never that data is correct or safe (I9).** The consumer MUST treat data as untrusted input; free-text
   data MUST NOT be interpreted as instructions.

Verification MUST NOT branch on `X.ust` beyond selecting the single 1.x algorithm (no downgrade, I10).

---

## 15. Error taxonomy

A verifier returns one of THREE OUTCOME KINDS — **availability is distinct from failure**:
- **VALID:LIGHT · VALID:HIGH · VALID:TOP** — verified, and the verdict CARRIES ITS TIER (the highest
  fully-satisfied rung, §3.1) so a consumer cannot read "valid" without reading valid-AT-WHAT: LIGHT = integrity +
  a claimed key; HIGH = + authoritative name; TOP = + anchored time. Stream COMPLETENESS is a RANGE verdict
  (§11.3 `verifyStream` → `complete: proven`), never a single-document claim — a document tier asserts the
  document's own axes only. Per-axis
  strengths (identity / time / completeness) remain below for detail. A BARE `VALID` is never emitted — that is
  the point (it forecloses the over-read "THIS is valid" when only the floor is).
- **INVALID** — a DEFINITE, deterministic negative (the document/chain is bad), terminal + fail-closed:
  `E-MALFORMED` (structure/namespace/identity), `E-CANON` (canonicalization/value-model), `E-BOUNDS`
  (size/depth/breadth), `E-CYCLE` (chain cycle), `E-SIG` (signature invalid / key_id mismatch), `E-KEY`
  (key-log chain BROKEN or entry unauthorized), `E-GENESIS` (FORKED / conflicting name-binding root — a rival
  genesis exists), `E-ANCHOR` (inclusion proof PRESENT-but-WRONG), `E-COMMIT` (commit ↔ decryption mismatch),
  `E-ROOT` (attestation root mismatch), `E-SEED` (derivation seed ≠ recomputed seed over `based_on` hashes),
  `E-PREV` (broken sequence link / checkpoint contradiction).
- **INDETERMINATE (`unavailable` | `unsupported_alg`)** — a check could NOT COMPLETE: a dependency was
  UNREACHABLE (genesis / key-log / anchor mirror down), or an OPTIONAL registry algorithm (§17 MTI) is not
  implemented by this verifier (`unsupported_alg`): NOT a negative. The document keeps its LIGHT verdict;
  the affected strength is reported `unavailable` (retry). Fail-closed means "never CLAIM a strength you did not
  verify" — it does NOT mean "call it INVALID." A verifier/MCP MUST NOT report an unreachable authority as a
  failed document. The reason set is CLOSED — {`unavailable`, `unsupported_alg`}: a fetch timeout IS
  `unavailable`; a verification-budget overrun is INVALID `E-BOUNDS` (§13); a fetched-but-WRONG dependency is
  its own definite error; an above-floor document without a TRUSTED capacity grant is `unavailable` (§13
  ladder). **`resource_limit`** (rc.12) is the third and last member: the document may be protocol-valid but
  exceeds THIS verifier's declared capability, or the raw input exceeds the transport admission budget —
  verification was refused or could not complete on THIS implementation; retry on a bigger verifier. A verifier
  MUST NOT mint new INDETERMINATE reasons.
Producers/MCPs SHOULD map the three kinds distinctly (INVALID ≈ 4xx deterministic; INDETERMINATE ≈ 503 retry).

---

## 16. Conformance

Conformance is TIERED (§3). The FLOOR (LIGHT) MANDATES only: a well-formed, string-only, bounded,
domain-separated, SIGNED, addressable State (§4–§10, §13) with the pubkey carried in `sig.pub`. HIGH adds
name authority (genesis/key-log); TOP adds anchored time. Stream **completeness** is a SEPARATE RANGE
verdict (`verifyStream` → `complete:proven`), NEVER part of a single document's tier (§11.3/§15). Every verifier REPORTS the tier
reached; a document does NOT change format across tiers OR roles — even genesis and key-log entries are UST transcripts (`class:"genesis"`/`"key"`, §12): ONE wire shape, universally, so a single §14 verifier checks the data AND the trust layer.

- **Conforming producer — LIGHT (the floor):** sign your canonical addressable JSON — emit a document per
  §4–§10 with a mandatory signature over a CARRIED key (`sig.pub`), string-only values, per-partition hashing,
  within bounds. NO genesis / anchor / completeness required. (This is the ~0.29-light adoption floor: publish
  in a minute.)
- **Conforming verifier — LIGHT:** recompute canonical + per-partition hashes + strict-Ed25519-verify against
  the carried/pinned key, fail-closed, report identity strength `self-asserted`/`pinned`. Passes the FLOOR
  vectors (canonicalization/NFC/ordering, per-partition captured-vs-computed hashing, domain separation,
  strict-Ed25519 malleability, bounds/cycle, error codes).
- **HIGH producer/verifier:** + genesis-rooted key log → `authoritative` identity, rotation/revocation
  (vectors: key-log chain, revocation window, genesis fork/recovery).
- **TOP producer/verifier (notary):** + anchor-proof per registered substrate (time) + sequenced-stream
  completeness. This is what noosphere runs.

Every verifier passes the normative test-vector suite BYTE-FOR-BYTE (§App. A) for the tiers it implements:
FLOOR vectors — canonicalization/NFC/ordering, per-partition captured-vs-computed hashing, domain separation,
strict-Ed25519 malleability, bounds/cycle, private-commit + AEAD↔commit binding, each error code. HIGH vectors —
key-log chain (self-signed rotation, break/unauthorized reject, ≤256 bound, revocation window, genesis
fork/recovery), name-authority resolution. TOP vectors — anchor-proof per substrate (non-final ⇒ UNPROVEN),
stream-genesis + checkpoint/omission, pinned Merkle/seed ordering. A verifier that diverges on any vector for
a tier it claims is non-conforming — making verifier disagreement a test failure, not a settlement weapon.
Independent re-implementation is expected; the vectors make "verify without trusting the publisher's library" real.

---

## 17. Registries

- **class:** `observation`, `attestation`, `derivation`, `genesis` (name-binding root, §12.1), `key` (key-log entry, §12.2). (Extensible by future 1.x; unknown ⇒ E-MALFORMED.)
- **key-log entry** (a `class:"key"` transcript, §12.2): `state.data.key_op.value` keys `op,pub,reason,compromised_since`; `op` ∈ `add|rotate|revoke`;
  `reason` ∈ `retired|compromised`. `key_id` = `H("ust:keylog", pub_raw)` (raw public-key octets, domain-separated §7 — not plain SHA256(pub)).
- **anchor substrate (operator choice, extensible):** an entry defines the substrate's `Locator` evidence
  fields, its public-append-only-log check, and its finality parameter. Registered: **`bitcoin-ots`**
  (`Locator = {substrate:"bitcoin-ots", ots:b64url, block_height:int}`; OTS attestation → Bitcoin header;
  finality = ≥6 confirmations) · **`rekor`** (`Locator = {substrate:"rekor", logIndex:int, inclusionProof:{
  logIndex, treeSize, rootHash, hashes[], checkpoint}, integratedTime:int}`; Sigstore transparency log →
  RFC 6962 inclusion to the signed tree head; finality = logged/immutable, seconds not hours; trusts the
  log operator's witness-cosigned tree head vs Bitcoin's trustless-but-slow). A verifier that understands
  SEVERAL substrates composes their plugins (`combineSubstrates`) — each returns the same `{final,time}`
  answer in its own dialect; an unknown substrate ⇒ `INDETERMINATE(unsupported)`, never INVALID. Future
  substrates register the same way — the protocol is substrate-agnostic. AnchorProof keys `root,path,anchor`.
- **partition kind:** `captured` · `computed` — BOTH bind `domain_shard` (descriptive tag only; the domain-less `computed` mode was REMOVED in rc.2). **partition privacy:** `blinded` · `encrypted` (both cryptographic — what is HIDDEN in the signed state). A "secret URL" is a DISCLOSURE CHANNEL (§out-of-scope, G18), not a privacy mode; removed from the registry in rc.4.
- **alg (signatures):** `Ed25519` (strict, §7). **hash:** `sha256:` domain-separated (§7). **enc.alg (AEAD):**
  `AES-256-GCM` (**MTI — mandatory to implement**: every conforming verifier implements it),
  `XChaCha20-Poly1305` (OPTIONAL: a verifier that does not implement it MUST return
  `INDETERMINATE(unsupported_alg)` for a disclosure it cannot decrypt — never a silent skip, never INVALID). **hash domain tags:** `ust:state` (whole-State `content_hash`) | `ust:shard` (a per-partition hash, §4.4) | `ust:keylog|ust:checkpoint|ust:node|ust:leaf|ust:seed|ust:source`.
  All algorithm-tagged for agility (§19).
- **reserved keys:** transcript: `ust,state,sig,proof`; State: `id,time,data,hashes,provenance`; id: `domain_shard,ust_id,key_id,class,parent_ust`;
  partition-envelope: `kind,value,privacy,commit,enc` (enc: `alg,key_id,ct`); provenance: `sources,constituents,based_on,root,seed,prev`;
  sig: `alg,key_id,pub,sig`. Reserved names MUST NOT be used as partition or source names.

---

## 18. Security considerations (threat → invariant map)

Each historically-identified attack is closed structurally. NOTE the tier (§3.1): floor attacks (integrity/
canon/DoS) are closed at LIGHT; NAME-impersonation and time attacks are closed at HIGH/TOP.
- **18.1 Impersonation off-substrate** → I2 (mandatory signature: the KEY is authenticated on any substrate).
  NAME-impersonation (a self-asserted `domain_shard`) is closed only at HIGH (name authority, §12); at LIGHT the
  name is a self-asserted label and the verifier reports strength `self-asserted` (§3.1) — it is never claimed authoritative.
- **18.2 Poisoned/mutable discovery, key or repo swap, git-mapping rewrite** → I7 (root of trust = anchored
  log/key log). Referencing is directional and non-implicating (§9.3).
- **18.3 Canonicalization ambiguity / cross-language divergence / equivocation** → I4 + §5 (one form,
  strings-only) + §16 (byte-exact vectors).
- **18.4 Signed content laundering, incl. prompt injection into agents** → I9 (provenance ≠ safety; data
  untrusted; free-text never instructions). Verification raises no trust in data semantics.
- **18.5 Low-entropy private recovery / metadata leak** → I6 (nonce-blinding) + §10 (metadata minimization).
- **18.6 Verification DoS (JSON-bomb, cyclic/exponential chains)** → I5 + §13 + §9.5, and I10 fail-closed.
- **18.7 Frame-only signature / unsigned timing/root/version tampering, downgrade** → I1 (whole-State
  signature) + I10 (version-stable, no branch on attacker fields).
- **18.8 Reputation laundering via free-string source names** → I8 (bound source identity).
- **18.9 Immutable-liability (illegal/permanent data, erasure conflict)** → §10/§11: only hashes anchored;
  ciphertext/raw in erasable store; erasure orphans the hash (data removable, proof intact).
- **18.10 Partition/identity structural collision** → I3 (namespace isolation; collision unrepresentable).
- **18.11 Grief via induced seal delay** → §11 signed-gap records make sustained gaps provably honest;
  operators SHOULD provide an anchor path independent of any single upstream.
- **18.12 Rival key-log impersonation (N1)** → §12.1 witnessed genesis (I11); anchor gives time/order, name
  authority requires DNSSEC/transparency/TLS-genesis. E-GENESIS on fork.
- **18.13 Anchor-discovery via mutable index (N4)** → §11.2 in-band inclusion proof (I12); the proof IS the mapping.
- **18.14 Silent frame omission (N5)** → §11.3 hash-linked `prev` + signed checkpoints, FOR operators offering
  the completeness guarantee (E-PREV on break); a non-sequenced operator makes no completeness claim (strength `none`).
- **18.15 Presentation two-truths via unsigned `view` (N3)** → `view` DELETED; rendering derives from the signed state.
- **18.16 Encrypted decryption≠commitment (N2)** → §10 AEAD binding; E-COMMIT if decryption ≠ committed plaintext.
- **18.17 Signature-layer malleability (N6)** → §7 strict Ed25519 + §16 vectors; one acceptance rule.
- **18.18 Commit-namespace overload (N7)** → commitment under `privacy`, data is purely partitions (I3).
- **18.19 Resolution DoS (N8)** → §13 key-log walk bound + inclusion proof removes anchor lookup; fail-closed.
- **18.20 Future/back-dated signed timing (N9)** → §11 timing is asserted; anchor is the only bound; `generated_at ≤ anchor`.
- **18.21 Discovery-driven SSRF (untrusted `domain_shard` steers the verifier's fetch)** → a resolver that
  auto-fetches discovery/witness surfaces (§12.1a/§20.1) takes its fetch TARGET from an attacker-suppliable
  document. Before ANY discovery egress it MUST admit only public DNS names: reject IP literals,
  localhost/reserved suffixes (`.local`, `.internal`, `.onion`, …), ports and paths — refusing to fetch
  (⇒ `unavailable`), never fetching. An offline mode MUST disable discovery egress entirely.

**Residual & honest limitations (explicitly stated, not hidden):**
- **Data ground-truth & Sybil (Y2)** — a source may lie faithfully; mitigated SOCIALLY by NON-COLLUDING,
  independently-CONTROLLED operators corroborating the same public source — NOT cryptographically. UST provides
  NO Sybil resistance: HIGH proves "this key controls this NAME," never "these names are distinct ENTITIES,"
  and genesis costs ≈ a domain registration, so one actor cheaply runs many "authoritative" domains (incl.
  affiliated engines). "Independent" is an out-of-band property the protocol cannot verify; a same-owner chain
  is a mechanism DEMONSTRATION, not evidence of independent agreement.
- **Confirmation is public by design; hiding data is the publisher's choice (Z1/Z3).** UST confirms the FACT
  of a sealing (existence, `ust_id`, `class`, partition names, lineage) — that is what it exists to do, and it
  is public. Hiding the VALUES is the publisher's option (§10), and its integrity depends on a UNIQUE-per-commit
  nonce (Z2). UST is not an anonymity/unlinkability system and does not claim to be: it is honest that it
  confirms the fact rather than conceals it. A publisher who needs the fact/timing itself hidden should not
  publish that fact — the data is on the publisher.
- **Anchored time depends on the OPERATOR's substrate, not the protocol (H8).** Identity & integrity are
  self-contained (State + key log). Verifying TIME means verifying the operator's chosen substrate (§11.2/§17)
  — for noosphere's `bitcoin-ots`, running/trusting a Bitcoin header source. So "verify without trust" is
  self-contained for identity+integrity, and for time DELEGATES to whatever the operator's substrate requires.
- **Time resolution is a SUBSTRATE property (H9).** e.g. `bitcoin-ots` finality (~1 hour at ≥6 conf) makes
  noosphere's anchored time hour-grade and lagged; sub-hour ordering rests on the signed-but-upper-bounded
  `generated_at` + the `prev` chain. A different registered substrate could offer different resolution.
- **The naming root is DNS/TLS PKI (H10).** UST removes PER-DOCUMENT transport trust (I2), but NAME authority
  bootstraps ONCE on DNSSEC/TLS + a transparency witness (§12.1). Everything bootstraps from something; UST is
  honest that its something is the naming system, used once at genesis, not per record.
- **Stolen-genesis fraud window (W2)** — whoever holds the genesis key can rotate in a new operational key, so a
  stolen genesis key (before a domain-control re-root) can sign fraudulent `authoritative` records. Not
  cryptographically eliminable, but BOUNDED + DETECTABLE: the rotation is an anchored/witnessed key-log entry,
  so an unauthored rotation is publicly visible → monitor the witness and re-root via domain control (§12.1 P2).
  Mitigate with a Shamir quorum on the genesis key (a single custody compromise cannot use it).
- Also out of scope: key custody; substrate liveness; economic abuse of open tiers.

**Onboarding on-ramp (RESOLVED — see §3.1 explicit LIGHT/HIGH/TOP tiers).** The protocol
floor is identity+integrity (signed well-formed State), and the heavier notary guarantees — TIME (anchoring),
COMPLETENESS (sequenced streams), NAME-AUTHORITY-at-scale (witnessed genesis) — are OPERATOR tiers surfaced as
verification STRENGTHS (§16). A small operator onboards at the floor and adds guarantees as it grows; the
security floor is always mandatory, the strengths are the gradual on-ramp. (The "heavy machinery" concern of
H11 was really me counting operator guarantees as protocol conformance — same class as the Bitcoin/substrate
layering fix, REV6.)

- **Y5 — equal commitments leak equality (bounded).** Two blinded/encrypted partitions committing the SAME
  (value, nonce) pair produce identical commitments/ciphertexts across documents; a verifier cannot detect
  producer nonce reuse (Z2, §10). The leak is bounded to EQUALITY, never content. Producers MUST use fresh
  nonces (I6); operators SHOULD keep a nonce log (§20). Within one document this cannot occur at all — the
  commitment binds the partition NAME, so two partitions never share a commit.

---

## 19. Versioning, migration, crypto-agility

- `ust` is the top-level scalar version marker `"MAJOR.MINOR"` (e.g. `"1.0"`, §4.1) — SIGNED (inside
  `canon({ust,state})`, no downgrade). A chain MAY mix versions (each document verifies under its own `ust`). A verifier for `1.y` MUST accept any `1.x` with `x ≤ y`
  and MUST REJECT `1.x` with `x > y` (E-MALFORMED) rather than guess an unknown future minor (M10) — additive
  minors mean older docs verify unchanged, but a verifier never processes rules it doesn't have. Unknown MAJOR
  ⇒ E-MALFORMED. Verification runs ONE algorithm within a major and never weakens for an older minor (I10).
- **Crypto-agility:** hashes and signatures are algorithm-tagged (`sha256:`, `Ed25519`). On a primitive break,
  the operator RE-ANCHORS existing roots under a new algorithm, citing the OLD append-only-log commitment as
  proof of pre-break existence — a signed, dated migration event, never a silent re-hash (which would be
  indistinguishable from forgery). `key_id` inherits this agility from its VALUE, not its tag: the H() output
  self-describes its algorithm (`sha256:…` today, a future primitive yields a new prefix under the SAME
  `ust:keylog` domain-separation string), so cross-algorithm confusion is precluded by the prefix and no
  re-tagging is ever needed. Migrating an IDENTITY to a new primitive is the §12.1 re-rooting event.
- **Migration from 0.x:** 1.0 re-roots identity in the mandatory whole-State signature and the namespaced
  shape; it is a clean break at a declared `ust_id`. Historical 0.x records remain verifiable under the 0.x
  algorithm and are referenced from 1.0 chains by `content_hash`.

---

## 20. Operator profile (instantiation boundary)

Discoverable from `domain_shard` (`/.well-known/ust`, corroborated against the anchored key log, §12) and
declaring the operator's choices, none of which relax §3: signature scheme + key-log location; anchoring
substrate(s); partition schema (names + captured/computed designation); source registry; cadence; the
hour-close timeout (§8.1); checkpoint cadence for sequenced streams (§11.3 — SHOULD for any stream that wants
provable completeness); a private-nonce uniqueness log (§10 I6/Z2 — SHOULD: the verifier cannot detect
cross-document nonce reuse, so the operator must); size bounds
(within §13 ceilings); metadata-minimization policy. A profile SHOULD publish §12.1 recovery events in a
changelog: unanchored records near a recovery boundary fail HIGH by design (X3) — consumers must be able to
see why, not guess. The protocol fixes the mechanism; the profile carries the
operator. Reference operator (noosphere.md) profile: `noosphere-engine/rnd/noosphere-operator-profile.md`.

### 20.1 Genesis discovery — the publisher SERVING contract

How genesis bytes are SERVED is operational and infrastructure-agnostic: per §1 the fetch path MUST NOT
affect verification — §14 is unchanged by anything here, and an unreachable root stays INDETERMINATE
(`unavailable`, §15). Verification already handles unavailability SAFELY; this contract makes it RARE. It
standardizes WHERE a dns-name publisher exposes its genesis and WHAT PROPERTIES that surface holds, so
ceremonies, verifiers and tooling interoperate without prescribing any vendor or stack (shared hosting, a
corporate cloud, any CDN, a bare nginx all conform). It applies to dns-name `domain_shard`s only (§4.3a —
a key-form identity is self-certifying and has no name to discover under). Economic abuse of open surfaces
is explicitly outside the §18 threat model; THIS is where it is addressed, operationally.

**Standard locations (the discovery pair):**
1. **HTTPS** — `https://<domain_shard>/.well-known/ust-genesis`: the EXACT bytes of the genesis transcript
   (§12.1-2 binds identity at this location; this contract governs its serving).
2. **DNS** — `_ust.<domain_shard>` TXT `ust-genesis=<content_hash>`: the standard record name and format.
   Under DNSSEC this record IS the §12.1-1 name-binding root; WITHOUT DNSSEC it is tamper-evident
   corroboration and mirror resolution ONLY — plain DNS proves nothing to a verifier (I7).

**Companion surfaces (same host, same contract):** a publisher offering out-of-the-box HIGH SHOULD also
serve `/.well-known/ust-keylog` — the §12.2 key log as a JSON array of its entry transcripts, in chain
order — and `/.well-known/ust-witness` — the §12.1a witness log. Both are APPEND-ONLY (existing entries
byte-stable; new entries/anchors appended); the genesis alone is fully immutable. Neither surface is a
verification input by itself: the key log re-verifies per §12.2 (every entry is a signed transcript) and
the witness log is an index whose anchors are substrate-checked (§12.1a) — a poisoned surface can deny
availability, never forge authority. The serving properties below apply to all three HTTPS surfaces.

**Serving properties — a publisher claiming discovery conformance MUST hold all four. Each is a PROPERTY;
the mechanism is the publisher's choice:**
- **Immutable bytes.** The genesis is content-addressed; the endpoint serves it as an immutable resource.
  After a §12.1 supersession the endpoint serves the CURRENT genesis and the DNS record carries its hash;
  the profile declares the propagation bound (how stale the pair may be after a supersession).
- **Query-robustness.** The response — and the endpoint's cache identity — MUST NOT vary with unrecognized
  query parameters: the cache key is the path (or an explicit, published allowlist). This forecloses
  cache-key amplification — per-request forced origin work, a cost-DoS that can price the discovery
  surface out of availability exactly when a verifier needs it. Edge-strip, origin normalization, a CDN
  rule or a proxy cache-key map all conform; the property, not the mechanism, is normative.
- **Vendor-independence.** Availability of the genesis bytes MUST NOT depend on ONE serving vendor: at
  least one INDEPENDENT mirror of the exact bytes exists. Because the genesis is content-addressed, a
  verifier MAY fetch from ANY mirror and accept the bytes iff their `content_hash` equals the expected
  value (pinned, from the DNS record, or from the well-known root). Mirrors carry AVAILABILITY, never
  AUTHORITY — name authority resolves ONLY per §12.1 (name-binding root + positive witness confirmation).
- **Method floor.** Plain `GET` (SHOULD also `HEAD`). Discovery is deliberately the simplest possible HTTP
  surface; parametrized query/verify transports are a SERVICE surface, out of scope here.

**Compliance attestation (informative).** A ceremony tool or auditor checks a discovery-conformance claim
by: (1) fetching the well-known and VERIFYING the transcript (§14, fail-closed); (2) matching its
`content_hash` against the DNS record (when present) and the expected/pinned value; (3) probing
query-robustness — a random unrecognized parameter MUST yield byte-identical content (and, where cache
metadata is observable, MUST NOT key a distinct cache entry); (4) hash-matching each declared mirror. The
reference ceremony (`ust genesis`) performs (1)–(2) fail-closed today; (3)–(4) are its natural extension.

---

## 21. Worked examples (informative)

One shape, five shorts across domains and modes. All obey §4–§10: string leaves, namespaced `data`,
whole-`state` signature. (`sig`/hashes abbreviated.)

### 21.1 Derivation that CHAINS to another publisher (by content hash, not URL)
A Muuune sound-state derived from Helioradar's reading — `based_on[].hash` is authoritative; `url` is advisory.
```json
{ "ust": "1.0",
  "state": {
    "id": { "domain_shard":"muuune.com", "ust_id":"ust:20260424.15", "key_id":"sha256:11a…", "class":"derivation" },
    "time": { "generated_at":"2026-04-24T15:03:20Z", "valid_from":"2026-04-24T15:00:00Z", "valid_to":"2026-04-24T16:00:00Z" },
    "data": { "sound": { "kind":"computed", "value":{ "chord":"Am7add9", "noise_color":"brown", "texture_mode":"WHITE_AMBIENT", "tithi":"8" } } },
    "hashes": { "sound":"sha256:…" },
    "provenance": {
      "based_on": [ { "hash":"sha256:<helioradar content_hash>", "url":"https://helioradar.com/ust/20260424.15" } ],
      "seed": "sha256:<H_seed over the based_on hashes>" } },
  "sig": { "alg":"Ed25519", "key_id":"sha256:11a…", "sig":"…" } }
```

### 21.2 Attestation — a sealed hour over N constituents
A notary-grade seal: `class:"attestation"`, `constituents` = the frame hashes, `root` = their Merkle root,
`prev` links the stream. No data of its own (content lives in the constituents + root).
```json
{ "ust": "1.0",
  "state": {
    "id": { "domain_shard":"noosphere.md", "ust_id":"ust:20260424.15", "key_id":"sha256:aa…", "class":"attestation" },
    "time": { "generated_at":"2026-04-24T16:00:30Z", "valid_from":"2026-04-24T15:00:00Z", "valid_to":"2026-04-24T16:00:00Z" },
    "data": { "seal": { "kind":"computed", "value":{ "frame_count":"120", "tier":"hour" } } },
    "hashes": { "seal":"sha256:…" },
    "provenance": {
      "constituents": [ "sha256:<slot 1>", "sha256:<slot 2>", "…", "sha256:<slot 120>" ],
      "root": "sha256:<Merkle root, byte-ascending>",
      "prev": "sha256:<previous hour attestation>" } },
  "sig": { "alg":"Ed25519", "key_id":"sha256:aa…", "sig":"…" } }
```

### 21.3 Private shard — prove it existed, without revealing it
A partition is PRIVATE per §4.4: its `value` is replaced by a blinded `commit` (inside `data`), signed and (optionally) anchored. Public parties get
existence+time; only a holder of the nonce reproduces the commitment.
```json
{ "ust": "1.0",
  "state": {
    "id": { "domain_shard":"acme-trading.com", "ust_id":"ust:20260424.153000", "key_id":"sha256:c3…", "class":"observation" },
    "time": { "generated_at":"2026-04-24T15:30:01Z", "valid_from":"2026-04-24T15:30:00Z", "valid_to":"2026-04-24T15:30:30Z" },
    "data": { "position": { "kind":"captured", "privacy":"blinded", "commit":"sha256:<H_shard({domain_shard,ust_id,nonce,partition,value})>" } },
    "hashes": { "position":"sha256:<over the commit>" } },
  "sig": { "alg":"Ed25519", "key_id":"sha256:c3…", "pub":"b64url", "sig":"…" } }
```

### 21.4 Transcript WITH a self-contained time proof (anchored)
The same observation plus an `AnchorProof` → time-strength `anchored` without any mutable lookup.
```json
{ "ust": "1.0", "state": { "…": "as §4.5" },
  "sig":   { "…": "…" },
  "proof": {
    "root": "sha256:<batch Merkle root>",
    "path": [ {"dir":"R","hash":"sha256:…"}, {"dir":"L","hash":"sha256:…"} ],
    "anchor": { "substrate":"bitcoin-ots", "ots":"base64url(OTS attestation)", "block_height":901234 } } }
```

### 21.5 An encrypted shard — ciphertext bound to the commitment
Carries ciphertext for authorized decryption; the AEAD block is bound to the SAME plaintext the `commit`
commits to (decryption and commitment can never diverge).
```json
{ "ust": "1.0",
  "state": {
    "id": { "domain_shard":"acme-trading.com", "ust_id":"ust:20260424.153000", "key_id":"sha256:c3…", "class":"observation" },
    "time": { "generated_at":"2026-04-24T15:30:01Z", "valid_from":"2026-04-24T15:30:00Z", "valid_to":"2026-04-24T15:30:30Z" },
    "data": { "book": { "kind":"captured", "privacy":"encrypted", "commit":"sha256:<H_shard({domain_shard,ust_id,nonce,partition,value})>",
                           "enc": { "alg":"XChaCha20-Poly1305", "key_id":"sha256:kk…", "ct":"base64url(ciphertext)" } } },
    "hashes": { "book":"sha256:<over the commit>" } },
  "sig": { "alg":"Ed25519", "key_id":"sha256:c3…", "pub":"b64url", "sig":"…" } }
```

---

## Appendix A — normative test vectors
The conformance suite (§16) ships at `spec/vectors/conformance-vectors.json` (starter: floor canon +
per-partition/content hash + Ed25519 sig-valid/tampered + canon-reject×3 + bounds; expanded with the reference
impl). It is normative: canonicalization vectors,
bounds/cycle vectors, signature verify/reject vectors, key-log resolution vectors, private-commit vectors,
attestation-root vectors, and one vector per error code (§15). A verifier is conforming iff it reproduces all
of them byte-for-byte. The STARTER suite has SHIPPED (11 vectors: floor canon + per-partition/content hash +
Ed25519 sig-valid/tampered + canon-reject×3 + bounds + two full documents `doc-01` VALID / `doc-02` tampered,
independently agent-verified). The FULL suite (strict-Ed25519 malleability, key-log resolution, anchor-proof
per substrate, one-per-error-code) is pending the `ustate` reference implementation.

---

## Appendix B — Revision history & finding→fix ledger

v1.0 was authored clean-room from the shipped v0.29 (reconciled to the live engine) and hardened across MULTIPLE
red-team passes (attack + consistency); each finding was closed STRUCTURALLY (invariant/mechanism), not patched. The inline `(N#)`,
`(M#)`, `(P#)`, `(H#)`, `(Q#)` markers in the text trace each clause to its finding; they are internal
provenance and will be lifted into this ledger when the spec is published.

- **REV 1** — clean-room rewrite from v0.29 + the pass-1–3 audit (34 external findings, 8 kill-chains, 4
  meta-patterns). Established invariants I1–I10, the positive whole-State signature, namespaced shape.
- **REV 2** — red-team of the rewrite (N1–N10): witnessed genesis, in-band anchor proof, sequence linkage,
  `view` deleted, commitment→`privacy` + AEAD binding, strict Ed25519, bounded resolution. Added I11/I12.
- **REV 3 / FINAL-mechanism** — lifecycle red-team (M1–M10): genesis-rooted self-signed key-log, name-binding
  genesis, anchor trust profile, stream-genesis, checkpoints, domain-separated hashing, pinned ordering/encodings.
- **REV 4 / DEPLOYMENT-READY** — operational red-team (P1–P10): revocation retired-vs-compromised semantics,
  genesis recovery re-rooted in domain control, aggregate verification budget, pinned domain-sep byte layout,
  completeness tail/cross-tier/AEAD-misuse/key_id. Added I13/I14.
- **REV 5** — honest cover-to-cover pass (H1–H11): fixed the VALID-condition bug and hash-tag discipline, and
  stated the honest limitations (Bitcoin-SPV for time, ~1h resolution, DNS/TLS naming root).
- **REV 6** — layering fix 1 (owner): Bitcoin/OTS moved from protocol to an operator SUBSTRATE (registry-based,
  like the signature scheme); `bitcoin-ots` lives in noosphere's operator profile.
- **REV 7** — layering fix 2 (owner): time + completeness + name-authority are OPERATOR GUARANTEES surfaced as
  STRENGTHS; the protocol floor is a signed well-formed State. Dissolved the tiered-conformance question (H11).
- **REV 8** — full cover-to-cover consistency pass (Q1–Q10): propagated the REV6/7 model into §1/§3/§14/§16/§18.
- **REV 9 (evolution)** — owner: keep the securely-structured (namespaced) base but RESTORE all 0.29 FEATURES a
  clean-room detour had dropped (per-partition captured/computed hashing, `parent_ust`, shard-chain LAYERS,
  per-partition mixed privacy, secret-URL). A literal flat-029 revert first (archived) re-opened seams and was
  reverted; features were merged into the namespaced base instead (`rnd/feature-audit-029-vs-v1.0.md`).
- **REV 10** — LIGHT/HIGH/TOP trust tiers made explicit (§3.1); full pass (G1–G17) propagated the tier + per-partition model.
- **REV 11–13 (owner form work)** — `ust`→top-level scalar marker (self-identifying, signed); `claim`→`state`;
  `payload`→`data`. Frozen wire: `{ ust, state{id,time,data,hashes,provenance?}, sig, proof? }`.
- **REV 14** — full red-team found F1 (CRITICAL): the two-scope split had made `content_hash` frame-identity
  (non-unique) while anchor/chain/prev/revocation key on it. Reverted to ONE unique `content_hash =
  H_state(canon({ust,state}))`; cross-engine stays per-partition (`rnd/red-team-rev13-full.md`).
- **REV 15** — 2nd full red-team (mechanism holes): G19 (`hashes`⇄`data` bijection), G20 (layer-seed
  self-reference), G23 (frame-bound private `commit`), G18/G25 (`rnd/red-team-rev14-full.md`).
- **REV 16** — pass 3 (mechanism INTERACTIONS): X1 (revocation vs anchor-upper-bound), X2 (completeness≠validity),
  X3 (genesis-epoch needs anchor), X4 (LIGHT has no revocation) (`rnd/red-team-rev15-interactions.md`).
- **REV 17** — pass 4 (economic/scale/collusion) + "UST is trust infrastructure" framing: Y1 (multi-commit
  grinding → completeness), Y2 (same-owner Sybil honesty), Y3 (LIGHT name≠attribution), Y4 (inbound refs confer
  nothing) (`rnd/red-team-rev16-economic.md`).
- **REV 18/19** — pass 5 (privacy/metadata) + owner correction: Z2 (unique-per-commit nonce) kept; Z1/Z3
  (metadata public) rolled back as DESIGN not bugs — UST confirms the fact, hiding data is the publisher's
  choice (`rnd/red-team-rev17-privacy.md`).
- **REV 20** — agent-verify caught a real bug: `key_id` byte-encoding was unpinned (a sample generator mangled
  the pubkey bytes); pinned `key_id = H("ust:keylog", pub_raw)`. Two independent agents then verified offline.
- **REV 21** — owner: ONE wire shape across tiers AND roles → genesis (`class:"genesis"`) and key-log entries
  (`class:"key"`) are UST transcripts; §12 unified; HIGH tier staged end-to-end.
- **REV 22** — MCP: availability ≠ failure → three outcome kinds VALID / INVALID / INDETERMINATE(`unavailable`);
  §14/§15 split unreachable (retry) from failed (deterministic).
- **REV 23** — pass 6 (HIGH identity × availability): W1 (suppress-the-witness fail-open → `authoritative`
  requires POSITIVE no-fork confirmation), W2 (stolen-genesis window, bounded), W3 (class-context enforcement)
  + macOS genesis-key-ceremony (`rnd/red-team-rev22-high-availability.md`).
- **REV 24** — GLOBAL consistency pass (V1–V6): propagated the availability split into §12.2 (V1) + stragglers
  (`rnd/red-team-rev23-global.md`).
- **REV 25 (2026-07-05)** — 4th external audit (ChatGPT 5.5 Max) hardening: key-binding by KEY not a string, TOP
  needs a genesis origin, embedded proofs fail-closed, class↔schema enforced, canon strict on member NAMES too,
  a raw-bytes verify boundary, `ust_id` pinned to valid frames, and `secret-url` removed (a disclosure channel,
  not a privacy mode). PLUS: the verdict now CARRIES ITS TIER — `VALID:LIGHT` / `VALID:HIGH` / `VALID:TOP`, never
  a bare `VALID` (§3.1, §15) — the `publisher_claimed` forcing function applied at the verdict level.
- **REV 26 (2026-07-12)** — resource-bound ladders (rc.10–rc.12): partition-capacity ladder (floor 64 /
  genesis-declared / ABS 4096), transcript-SIZE ladder (floor 1 MiB / genesis-declared / ABS 64 MiB) with the
  VOLUME-vs-STRUCTURE classification (§13), ONE normative size metric (UTF-8 bytes of the signed content),
  capacity as a TRUSTED GRANT (authority-resolution output, never a raw caller-attached genesis),
  `resource_limit` as the third INDETERMINATE reason (§15), and accurate producer guards.
- **REV 27 (2026-07-12)** — genesis discovery formalized as a publisher SERVING contract (§20.1, operational —
  per §1 fetch never affects verification): the standard discovery pair (`/.well-known/ust-genesis` +
  `_ust.<domain_shard>` TXT `ust-genesis=<content_hash>`, cross-pinned in §12.1), four infrastructure-agnostic
  serving properties (immutable bytes; query-robustness — cache identity independent of unrecognized query
  parameters, foreclosing cache-key amplification; vendor-independence — content-addressed mirrors carry
  AVAILABILITY never AUTHORITY; GET method floor), and the compliance-attestation procedure the ceremony
  tooling performs. Driven by a live outage: a billing-suspended front-end host took the reference operator's
  discovery surface down while the notary path stayed healthy — the serving layer must never be a
  single-vendor dependency.
- **REV 28 (2026-07-13)** — the witness made MECHANICAL (§12.1a): a normative serving shape
  (`/.well-known/ust-witness`, an append-only genesis log whose entries carry §11.2 `AnchorProof`s — one
  verification path, no new mechanism) plus the verifier auto-query (exactly-one anchored active genesis ⇒
  positive no-fork confirmation; two, or a differing one ⇒ E-GENESIS; zero verifiable ⇒ `unavailable`,
  authoritative DENIED, W1) — no-fork becomes COLLECTED EVIDENCE and HIGH the honest zero-step default.
  The endpoint is an INDEX, never an authority: anchors are substrate-checked (§17 — `rekor` registered
  alongside `bitcoin-ots`; a verifier composes substrate plugins, unknown ⇒ INDETERMINATE(unsupported)).
  §20.1 gains the companion serving surfaces (`ust-keylog`, `ust-witness`, append-only). §18.21 names the
  discovery-driven SSRF threat: an auto-fetching resolver MUST admit only public DNS names before egress.
  Shipped and live-proven across all three reference surfaces (CLI, MCP, web) against the reference
  operator before this REV was written — spec text follows running code, not the reverse.
- **REV 29 (2026-07-13)** — external security audit (#69) folded in STRUCTURALLY. No normative text
  changed: the audit found the reference IMPLEMENTATION was not enforcing requirements the spec already
  declared, so the code caught up (one root cause — a proof of self-consistency was being accepted where
  external anchoring is required). (A) The substrate plugins now TERMINATE at the external trust root, not a
  self-consistent object: `@ust-protocol/rekor-verify` verifies rekor.sigstore.dev's SIGNED checkpoint with a
  pinned log key (a fabricated `treeSize=1` tree is rejected — reproduced), `@ust-protocol/ots-verify`
  verifies the committed root against a REAL Bitcoin block header + the §17 ≥6 confirmations (not just
  `isTimestampComplete()`); the web verifier gained the same checkpoint check. (D) The discovered key-log
  crosses the SAME raw-byte boundary as any authority input (I4) — a duplicate member is E-CANON, never a
  silent LIGHT. (E) A single async anchor contract (`verifyAsync`, so TOP works with the async plugins while
  `verify()` stays sync); the exact signed-content size metric in the producer guard (no estimate pad) and in
  `checkBounds` (signed content, not the transport object); and a Node-side SSRF resolution guard (a public
  NAME resolving to a private ADDRESS is refused) layered over the portable lexical floor of §18.21.

**Design principle throughout:** every normative clause answers "mechanism (protocol) or operator
instantiation (profile)?"; operator specifics (substrate, partition schema, completeness, cadence) live in the
operator profile (§20), never the protocol. The five passes converged from "the protocol can be broken" to
"the operator must be told how to run it" — the signature of a settled design.
