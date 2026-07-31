// SPDX-License-Identifier: Apache-2.0
// CONSUMER PROBE (#117) — the shape of the question is the point: this file does what a TYPED consumer does, with
// the package's own declarations and NOTHING ELSE. No `declare module`, no shadowing, no `as` casts, no `any`.
//
// It exists because the rule we give consumers is *do not redefine the package you consume* — measured, a
// hand-written `declare module 'ust-protocol'` made a compiler see 15 names where the package exports 117, for
// months, with nothing able to notice. Consumers are right to delete those. The moment they do, this file is the
// promise they are left with, and `tsc --strict` decides whether we kept it.
//
// A cast here would defeat the whole probe: `as` is exactly the wrapper we are trying to make unnecessary.
import * as P from 'ust-protocol';

export function probe(): void {
  // ── 1. BUILD. A producer names three arguments and lets the guarded tail default. Before #117 this line did not
  // compile: every parameter was declared required, so it demanded nine arguments for a call the runtime accepts.
  const genesis = P.buildGenesis({ domain_shard: 'example.com' }, '2026-07-31T12:00:00Z', 'pub-b64url', 4096);

  // ── 2. CANONICALISE + ADDRESS. Both are string-returning primitives, and a consumer uses them as strings.
  const bytes: string = P.canon(genesis);
  const hash: string = P.contentHash(genesis);
  if (bytes.length === 0 || hash.length === 0) throw new Error('empty canonical form');

  // ── 3. VERIFY and READ THE VERDICT. This is the reason a consumer needs types at all: the verdict is a
  // CONTROL-FLOW value, not a display value — `isValid` decides whether the next line may run. `result` is a
  // DECLARED field now (#117), so reading it needs no guard and no cast; `id` is declared optional because a
  // failing verdict genuinely has none, which is the runtime measured rather than the specification read.
  const verdict: P.UstVerdict = P.verify(genesis);
  const result: string = verdict.result;
  if (result.length === 0) throw new Error('empty verdict');
  const ok: boolean = P.isValid(verdict);
  if (!ok) return;

  // ── 4. AN HONEST `unknown`, NARROWED — no cast. `ustGrid` returns `string[] | null` at runtime and the
  // generator will not claim that from a JavaScript body, so it says `unknown`. That is the promise we chose in
  // #116: a weak type a consumer can narrow beats a confident one that is wrong. This is what narrowing costs —
  // three lines, no `as`, and the compiler proves the result rather than being told.
  const grid: unknown = P.ustGrid('ust:20260731.12', 'ust:20260731.14', 3600);
  if (!Array.isArray(grid)) return;                       // null is a real outcome, not an error
  const slots: string[] = grid.filter((s): s is string => typeof s === 'string');
  if (slots.length === 0) throw new Error('empty grid');
}
