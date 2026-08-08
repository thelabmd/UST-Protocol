// SPDX-License-Identifier: Apache-2.0
// rev36 R4 — the witness-budget clock is a MONOTONIC ELAPSED-time faculty, owned by the verifier, NOT untrusted input.
//
// round-29 P0-02: exposing the clock as a public `opts.__nowMs` field let a CALLER expand the effective witness budget and
// flip resource_limit into a served-list VALID:HIGH. The clock therefore lives HERE, in an INTERNAL module that is NOT part
// of the package's public API (not in package.json `exports`; a wire caller passing a document cannot reach it).
//
// round-30 P1-01: the rev33 realization used `Date.now()` behind a non-decreasing WRAPPER (clamp a backward source to its
// last value). That is exactly what F.9 forbids — a wall-clock value with a monotone wrapper. On a backward step (an NTP
// correction on a real wall clock; a test rollback) the wrapper FROZE time at `_last`, so the whole-operation deadline was
// never reached and the aggregate budget DISAPPEARED, leaving only the per-leaf timers. A slow connector then confirmed.
//
// The fix is not a better wrapper but the RIGHT source: `performance.now()` is a MONOTONIC elapsed-time clock (milliseconds
// since an arbitrary epoch, guaranteed non-decreasing, immune to wall-clock/NTP correction). It cannot go backward, so it
// needs no wrapper and cannot freeze. The whole-op budget is measured as ELAPSED against an operation-local start
// (`opDeadline = witnessNow() + budget`, computed at op start), never a wall-clock deadline. `Date.now()` is not used.
//
// The conformance harness (and only it) imports this module directly to drive time deterministically with a MONOTONIC test
// clock, then restores the default — a code-level test capability, not a data-path surface.
//
// #143: `performance` is read from the GLOBAL, not imported from `node:perf_hooks`. It is a global in every browser, in Node
// since 16, and in every worker runtime — the import bought nothing and was one of the two reasons the core did not bundle
// for a browser. The clock's guarantee is unchanged: still `performance.now()`, still monotonic, still never `Date.now()`.
const monotonic = () => performance.now();
let _now = monotonic;

// The monotonic elapsed clock the witness budget reads. In production this is performance.now(); never Date.now().
export function witnessNow() {
  return _now();
}

// TEST-ONLY (conformance harness). NOT exported from index.mjs; not on the public API. Pass a MONOTONIC (non-decreasing)
// function to drive elapsed time deterministically; pass nothing to restore the real monotonic clock. Restore in a finally.
export function __setWitnessClockForConformance(fn) {
  _now = (typeof fn === 'function') ? fn : monotonic;
}
