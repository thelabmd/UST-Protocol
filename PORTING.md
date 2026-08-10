# Porting UST to your language

UST verification is small and portable — the value model is deliberately narrowed so the notorious
cross-language canonicalization traps mostly do not exist here. This guide tells you exactly what you must
reproduce byte-for-byte, and how to prove you did.

## Two rules this protocol does not trade away

**1. A minor only ADDS.** A change that alters the meaning of anything an earlier minor already defines is a **MAJOR**. There is no third option, and the reason is not taste: an older verifier evaluating under older rules must still be **right** about what it evaluated. A minor that changed a meaning would make every deployed verifier quietly wrong rather than merely less informed.

**2. A verifier never expires.** An older verifier keeps producing correct verdicts about everything it understands. Material from a newer minor that it does not implement is reported as **NOT EVALUATED** — never as invalid, and never silently passed. Whether that reach is sufficient is the **consumer's** policy (the `--require-*` floors), not the protocol's coercion.

**Why the second rule is load-bearing for adoption.** People run old runtimes for years because upgrading means reworking a stack that works. A protocol whose adoption depends on synchronised upgrades across every consumer has chosen a property it cannot have — and a verifier that must be current in order to verify anything is a verifier that stops being run. Refusing politely is still refusing.

**And it is what makes CLOSED systems possible at all.** A consumer with no discovery surface has no way to learn that the world moved. Under a refusal design it sees only *invalid*, with nothing pointing at its own age; under this one it keeps working, keeps being honest about what it did and did not check, and can run for years without ever lying.

*Both rules hold today. A newer minor answers `INDETERMINATE(unsupported_minor)`, a different major `INDETERMINATE(unsupported_major)`; `INVALID` is reserved for its one meaning — the verifier applied ITS OWN rules and they were violated.*

## The one hard part: canonicalization (and why ours is narrow)

A signature is over `S = canon({ust, state})` — a canonical UTF-8 string. Two implementations that canonicalize
differently produce different bytes, and signatures "don't match" even though the JSON looks identical. This is
the price of I4 ("two verifiers always agree"): deterministic text-signing needs ONE canonical form.

The generic JCS (RFC 8785) trap has a poisonous corner — **number formatting** (`1.0` vs `1e2` vs
`0.30000000000000004`). **It does not exist in UST.** The §5 value model forbids number / boolean / null leaves:
**every leaf is a string.** So the surface you must match is small and fully closeable:

| Canon rule | What to do |
| --- | --- |
| **Key order** | Object keys sorted lexicographically by UTF-16 code unit, recursively. Array order is significant and preserved. |
| **Whitespace** | None. No spaces after `:` or `,`, no trailing newline. |
| **Leaves** | Strings only. A number / boolean / null leaf ⇒ `E-CANON` (reject — it is not a valid UST value). |
| **String escaping** | Minimal JSON: escape `"`, `\`, and C0 control chars (`\n`, `\t`, …). Nothing else. |
| **Non-ASCII** | Kept as **UTF-8 bytes**, NOT `\u`-escaped. `café`, `日本語`, `🌍` stay literal. (This is the trap most JSON libraries fall into — many escape non-ASCII by default.) |
| **NFC** | Strings MUST be Unicode NFC. A non-NFC string ⇒ `E-CANON`. (The canon does not normalize for you — it rejects, so the divergence is visible.) |
| **Duplicate keys** | Reject on the RAW bytes before parsing (most parsers silently collapse duplicates) ⇒ `E-CANON`. |

That is the whole contract. No number formatting, no locale, no float rounding.

## Prove it: the vector arbiter

Do not argue about prose — run the vectors. [`vectors/conformance-vectors.json`](vectors/conformance-vectors.json)
carries `kind: "canon"` cases (`input` → `expect_canon`) and `kind: "canon-reject"` cases. Your implementation
conforms iff, for every canon vector, `your_canon(input) == expect_canon` **byte-for-byte**, and every
canon-reject vector throws. The `canon-03…canon-11` set covers exactly the edge cases above (key sort, nested
sort, array-vs-key order, object-in-array, escaping, control chars, BMP + astral Unicode, empty object/array).

When a byte differs, use the diagnostic:

```
npx @ust-protocol/cli canon your-input.json      # prints the canonical STRING + content_hash
```

Diff your output against that, and you see the exact divergence point (a stray space, a `é` where a literal
`é` belongs, an unsorted key) instead of a silent signature mismatch. The reference CLI's `ust canon` exists for
precisely this; a Go `ust canon` is PLANNED with the Go SDK (#34, not written yet) so cross-SDK diffs become one command.

## The crypto boundary (a design boundary, not a gap)

- **Verify needs ZERO crypto from you.** Call a conforming verifier (`ust-protocol` in JS or the
  `ust_verify` MCP tool — a second, independent implementation is PLANNED, #34, and does not exist yet) and read a machine verdict. You do not reimplement hashing or signature checking to
  *consume* UST.
- **Produce needs ONE primitive.** The build tools return `{ state, content_hash, signing_input }`. You do a
  single `Ed25519.sign(privkey, signing_input)` (RFC 8032, strict) and assemble
  `sig = { alg: "Ed25519", key_id, pub, sig }`. You do NOT reimplement canon or hashing — those come from the
  lib. A signing service holds **no** key (a shared signing key is a forgery oracle); the key stays with the
  producer. `@ust-protocol/web-signer` hides this for JS; other languages call their stdlib Ed25519 over the
  returned `signing_input`.

**If you DO write your own verifier: your Ed25519 library will not enforce §7/N6 for you.** Measured 2026-08-09
on three implementations — `node:crypto`, WebCrypto and Go's `crypto/ed25519` — against the reference edge-case
corpus (Chalkias, Garillot, Nikolaenko, *Taming the many EdDSAs*, 12 vectors). Two findings, and the second is
the one that matters to you:

- the three **agree on all twelve**, and all are cofactorless, so the classic "which EdDSA is this?" divergence
  did not appear between them;
- and all three **accept** small-order `A`/`R` and one non-canonical `A` — the encodings §7/N6 says to reject.

So a port that simply calls its stdlib verify is **not conforming**, in the same way ours was not until that
measurement. Both rejections are decidable on the wire bytes, no curve arithmetic required: small order is a
finite set of **eight** encodings, and canonicality is `y < p` **plus** the negative-zero case (`x == 0`, i.e.
`y ∈ {1, p−1}`, with the sign bit set). That second half is easy to miss — in the corpus, vectors 8–11 are
non-canonical *only* in that sense, their `y` is `p−1` and well inside the field, so a `y >= p` test alone
passes all four straight through. The `ed25519-point-admission` vectors in `vectors/conformance-vectors.json`
pin exactly this, and `admitEd25519Point` in the JS core is the reference implementation of it. Mixed-order
points stay ACCEPTED on purpose: §7/N6 does not forbid them, and rejecting them would need a subgroup check.

A port that only VERIFIES needs nothing above the base. A port that PRODUCES a stream will meet the same
state-over-time problems the JS operator layer already solves — prev-chains per tier, checkpoints with observed
interval bounds, and composition above the breadth law. `@ust-protocol/operator` is not normative and you are
free to ignore it, but its round-trip conformance is a useful oracle: every piece PRODUCES exactly what the base
VERIFIES, so a port can check itself against the same expectations.

Ed25519 note: RFC 8032 is deterministic **by construction** (the nonce is `H(prefix‖message)`, no RNG in
signing), so there is no RFC 6979 concern — the only entropy requirement is CSPRNG **key generation**.

## Recommended path

1. **Reuse, don't rewrite.** Most consumers call `ust-protocol` (JS) or the MCP. The
   canon trap only bites someone writing their OWN implementation.
2. If you DO write one: implement `canon`, pass every `canon` / `canon-reject` vector, then the `hash`,
   `key_id`, `commit`, `seed`, `merkle-root`, and `signature` vectors. `ust canon` is your byte-diff oracle
   throughout.
3. Match JS byte-for-byte on the vectors ⇒ portability is proven for your language. Go (#34) is the first
   PLANNED first non-JS SDK — it is not written, and until it is, this project has ONE implementation and says so
   (a second is what makes a differential test meaningful; claiming one that does not exist is the opposite of the
   independence it is supposed to buy). Rust / Python would follow the same pattern.

## Honest note

The canonicalization trap is INHERENT to deterministic text-signing — it is the cost of "two verifiers always
agree" (I4). UST narrows it to ~zero in practice (strings-only value model + an objective vector arbiter + a
byte-diff diagnostic), but it is reduced, not eliminated: a new implementation still has to match the vectors.
That is a feature — the vectors are the contract, and passing them is a definite, checkable fact.

## Display safety (rendering untrusted values)

Integrity is byte-exact, so invisible/RTL Unicode inside a VALUE is harmless to verification (bytes are bytes).
But a HUMAN RENDERER (a Pages viewer, an extension md-reader) must neutralize bidi / zero-width controls when
showing untrusted values — an RTL-override can flip displayed order and deceive the eye. Escape-first (already
required for HTML) plus neutralization of the whole Unicode FORMAT class `\p{Cf}` — not a list of codepoints: a
hand-list loses exactly one member, and the class is the domain (it also covers LRM, RLM, ALM, word-joiner and
soft-hyphen). Render each one visibly, e.g. `[U+202E]`, with a marker that carries no markup meaning so the two steps
commute. This is a display-safety rule for verifier UIs, not a
canon change; `domain_shard` names have the stronger A-label guard (§4.3a).
