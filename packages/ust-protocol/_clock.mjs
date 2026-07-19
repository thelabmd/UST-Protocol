// SPDX-License-Identifier: Apache-2.0
// rev33 R4 — the witness-budget clock is a VERIFIER-OWNED faculty, NOT untrusted input.
//
// round-29 P0-02: exposing the clock as a public `opts.__nowMs` field let a CALLER pass a non-monotonic clock through the
// DATA PATH (`verify`/`resolveByDiscovery` opts) and expand the effective witness leaf timeout, flipping a resource_limit
// into a served-list `VALID:HIGH`. The verifier's own resource measurement `ρ_v` (F.9) must not be caller-writable.
//
// The clock therefore lives HERE, in an INTERNAL module that is NOT part of the package's public API (not in
// package.json `exports`, never reachable from a `verify(doc, opts)` call — a wire caller passing a document cannot set
// it). Production uses a monotonic-guarded wall clock. The conformance harness (and only it) imports this module directly
// to drive budget-exhaustion deterministically, then restores the default — that is a code-level test capability, not a
// data-path surface.
const wall = () => Date.now();
let _now = wall;
let _last = -Infinity;

// The clock the witness budget reads. MONOTONE-GUARDED: a source that moves backward is clamped to its last value, so
// even a mis-set clock can never REWIND the deadline to grant a slow connector more time than a forward clock would.
export function witnessNow() {
  const t = _now();
  if (typeof t !== 'number' || !Number.isFinite(t) || t < _last) return _last === -Infinity ? (_last = wall()) : _last;
  _last = t;
  return t;
}

// TEST-ONLY (conformance harness). NOT exported from index.mjs; not on the public API. Pass a function to drive time
// deterministically; pass nothing to restore the wall clock. Always restore in a finally.
export function __setWitnessClockForConformance(fn) {
  _now = (typeof fn === 'function') ? fn : wall;
  _last = -Infinity;
}
