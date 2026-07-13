# Porting UST to your language

UST verification is small and portable — the value model is deliberately narrowed so the notorious
cross-language canonicalization traps mostly do not exist here. This guide tells you exactly what you must
reproduce byte-for-byte, and how to prove you did.

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
precisely this; a Go `ust canon` ships with the Go SDK (#34) so cross-SDK diffs are one command.

## The crypto boundary (a design boundary, not a gap)

- **Verify needs ZERO crypto from you.** Call a conforming verifier (`ust-protocol` in JS, the Go binary, or the
  `ust_verify` MCP tool) and read a machine verdict. You do not reimplement hashing or signature checking to
  *consume* UST.
- **Produce needs ONE primitive.** The build tools return `{ state, content_hash, signing_input }`. You do a
  single `Ed25519.sign(privkey, signing_input)` (RFC 8032, strict) and assemble
  `sig = { alg: "Ed25519", key_id, pub, sig }`. You do NOT reimplement canon or hashing — those come from the
  lib. A signing service holds **no** key (a shared signing key is a forgery oracle); the key stays with the
  producer. `@ust-protocol/web-signer` hides this for JS; other languages call their stdlib Ed25519 over the
  returned `signing_input`.

Ed25519 note: RFC 8032 is deterministic **by construction** (the nonce is `H(prefix‖message)`, no RNG in
signing), so there is no RFC 6979 concern — the only entropy requirement is CSPRNG **key generation**.

## Recommended path

1. **Reuse, don't rewrite.** ~90 % of consumers call `ust-protocol` (JS), the Go binary (#34), or the MCP. The
   canon trap only bites someone writing their OWN implementation.
2. If you DO write one: implement `canon`, pass every `canon` / `canon-reject` vector, then the `hash`,
   `key_id`, `commit`, `seed`, `merkle-root`, and `signature` vectors. `ust canon` is your byte-diff oracle
   throughout.
3. Match JS byte-for-byte on the vectors ⇒ portability is proven for your language. Go (#34) is the first
   official non-JS SDK; Rust / Python follow the same pattern.

## Honest note

The canonicalization trap is INHERENT to deterministic text-signing — it is the cost of "two verifiers always
agree" (I4). UST narrows it to ~zero in practice (strings-only value model + an objective vector arbiter + a
byte-diff diagnostic), but it is reduced, not eliminated: a new implementation still has to match the vectors.
That is a feature — the vectors are the contract, and passing them is a definite, checkable fact.

## Display safety (rendering untrusted values)

Integrity is byte-exact, so invisible/RTL Unicode inside a VALUE is harmless to verification (bytes are bytes).
But a HUMAN RENDERER (a Pages viewer, an extension md-reader) must neutralize bidi / zero-width controls when
showing untrusted values — an RTL-override can flip displayed order and deceive the eye. Escape-first (already
required for HTML) plus bidi-isolation in the reader view. This is a display-safety rule for verifier UIs, not a
canon change; `domain_shard` names have the stronger A-label guard (§4.3a).
