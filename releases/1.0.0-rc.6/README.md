<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Release evidence — ust-protocol 1.0.0-rc.6

`release-evidence.ust.txt` is a signed UST (`class: derivation`) binding this release's artifacts into one
verifiable object: the source **git commit**, the published **npm tarball integrity**, the **conformance
vectors hash** and the **machine test report** (`test-report.txt`, 74/0). Its `based_on` carries the audit
lineage: follow-up audit → rc.6 response → the original rc.5 audit — each a signed UST; walk the chain with a
resolver.

Verify: decode the base64 after `———UST(base64)———`, then `verify(doc, { context: "data" })` with
[`ust-protocol`](https://www.npmjs.com/package/ust-protocol), or paste the whole file into
[the web verifier](https://thelabmd.github.io/UST-Protocol/).

This implements P0-4 of the follow-up audit ("signed release evidence") as a MECHANISM, not a file:

```
node tools/release-evidence.mjs generate --based-on sha256:<audit-lineage head>   # collects everything itself
node tools/release-evidence.mjs check                                             # the gate — recomputes reality
```

`generate` hand-types nothing (commit = the registry's `gitHead` — the artifact's true source; integrity from
npm; hashes computed; tests run fresh) and refuses a red suite. `check` re-derives every bound value and exits 1
on any mismatch — run it before publishing anything. A release is not a claim, it is a verifiable chain.
