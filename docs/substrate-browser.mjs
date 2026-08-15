// SPDX-License-Identifier: Apache-2.0
// THE CONSUMER'S SUBSTRATE FACULTY, in a browser — supplied TO the core, never built into it.
//
// `ust-protocol` embeds no blockchain and no log client on purpose: a substrate is reached through
// `substrateVerify`, which the protocol declares a faculty of the CONSUMER. Node consumers install
// `@ust-protocol/ots-verify` or `@ust-protocol/rekor-verify`; both are node-only and say so. A page had nothing,
// which is why moving this verifier onto the reference implementation cost it the witness corroboration it used
// to have — measured 2026-08-15 against `noosphere.md`'s live files: `confirmed` before, `pending` after.
//
// This module is that faculty for a page. It is NOT a third implementation of anything: the two checks below
// already existed and were already exercised against a live log; what was missing was the adapter to the
// contract the core actually asks for.
//
// WHAT IT PROMISES, EXACTLY. The reference connectors return `{ final, time, reason }`, and the core admits a
// receipt only when `final` is an OWN Boolean `true` and `time` an OWN RFC3339-Z instant. Anything less is
// `unavailable` — honest, and never a verdict. This adapter matches those shapes rather than inventing its own,
// because a browser reaching a DIFFERENT answer from the package would be the cross-implementation split the
// whole canon discipline exists to prevent.
//
// WHERE IT IS WEAKER THAN THE PACKAGE, said plainly. The Node OTS connector requires >= 2 independent explorers
// to agree before calling a Bitcoin anchor final (`explorer-corroborated`). This one takes the first reachable
// explorer's answer, so it earns `explorer-single` — the SAME registered vocabulary, at the strength it actually
// holds. Labelling it `corroborated` would be an overclaim of exactly one word, which is how a tier gets
// inflated without anyone lying on purpose.
import { rekorFinal, bitcoinFinal } from './ust-resolve.mjs';

const isoZ = (unixSeconds) => new Date(unixSeconds * 1000).toISOString().slice(0, 19) + 'Z';

/**
 * `substrateVerify(anchor, root)` — the core's seam.
 *
 * Returns `null` for a substrate this build does not claim, which the core reports as `unavailable` rather than
 * as a refusal: not knowing a substrate is not evidence against a document. A refusal it CAN make carries the
 * registered reason naming which conjunct failed, so a reader learns who can act on it.
 */
export async function substrateVerify(anchor, root) {
  if (!anchor || typeof anchor !== 'object') return null;
  try {
    if (anchor.substrate === 'rekor') {
      const r = await rekorFinal(anchor, root);
      if (!r?.ok) return { final: false, time: 'unproven', reason: r?.reason ?? 'unreadable-entry' };
      // The time is the log's `integratedTime`, exactly as the Node connector reads it. The signed checkpoint
      // binds `rootHash` and `treeSize` — NOT this instant — so a TOP resting on it inherits the log operator's
      // time claim. That trade is the package's, and matching it is the point; making a different one here would
      // mean a page and a package disagreeing about the same anchor.
      const t = anchor.integratedTime;
      return { final: true, time: typeof t === 'number' ? isoZ(t) : 'rekor-logged', log_index: String(anchor.logIndex ?? '') };
    }
    if (anchor.substrate === 'bitcoin-ots') {
      const r = await bitcoinFinal(anchor, root, fetch);
      if (!r?.ok) return { final: false, time: 'unproven', reason: r?.reason ?? 'unreadable-entry' };
      // Trustless by construction: the block header is public consensus and the explorer is only a mirror of it.
      // The header's own timestamp is the anchored time — no operator's claim stands between it and the reader.
      return { final: true, time: isoZ(r.time), block_height: String(r.height), assurance: 'explorer-single' };
    }
  } catch {
    // A connector that throws must not become a verdict about the document (#144, and F.5.1's whole point):
    // an unreachable or malformed substrate is EVIDENCE this page could not obtain, not evidence against.
    return { final: false, time: 'unproven', reason: 'substrate-unreachable' };
  }
  return null;
}
