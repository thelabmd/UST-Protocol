// SPDX-License-Identifier: Apache-2.0
// @ust-protocol/rfc6962-verify — the RFC 6962 CONSTRUCTION connector for UST anchor proofs.
//
// UST's anchor evidence has TWO independent axes and §11.2 keeps them apart on purpose:
//   • SUBSTRATE  — "is this ROOT committed to the outside world, and when?"  (rekor, bitcoin-ots)
//   • CONSTRUCTION — "is this content_hash a MEMBER of that root?"           (ust-merkle-tagged, rfc6962-raw)
// The core bundles the reference construction (`ust-merkle-tagged`) and delegates every other one. This package
// is the delegate for `rfc6962-raw` — the tree Certificate Transparency uses and the one a live UST operator
// anchors with, while anchoring into BITCOIN.
//
// It lived inside `@ust-protocol/rekor-verify` until round 236, which made a consumer install a transparency-log
// client in order to check a publisher anchored in Bitcoin — a dependency that took no part in the check and
// misdescribed what was happening. Nothing here references rekor; the whole file is SHA-256 and RFC 6962
// arithmetic over bytes the caller already holds. No network, no substrate, no log.
//
// `@ust-protocol/rekor-verify` re-exports both functions, so an installed consumer keeps working unchanged.
import { createHash } from 'node:crypto';

const sha256 = (buf) => createHash('sha256').update(buf).digest();
const hexToBytes = (h) => Buffer.from(h.replace(/^sha256:/, ''), 'hex');

export function verifyInclusion(proof) {
  // totality (round-46 self-audit) — an inclusion proof is UNTRUSTED input: a null/hostile arg, a HOSTILE Proxy (a throwing getter
  // fires on the destructuring below), or a non-array `hashes` must be a structured `false` (proof does not hold), never a host
  // throw. Fail-closed (false = not proven). The whole read+recompute is guarded because a getter can throw at any field access.
  try {
    if (!proof || typeof proof !== 'object') return false;
    const { leafHash, index, treeSize, hashes, rootHash } = proof;
    // TREE INDICES ARE UNBOUNDED NATURALS AND MUST NOT BE NARROWED (rc.67).
    // RFC 6962 §2.1.1 defines the path over naturals and the wire form is uint64. JavaScript's >> and & coerce to
    // SIGNED 32-BIT, so any index at or above 2^31 goes NEGATIVE mid-climb. This verifier was correct for the whole
    // history of the public log and broke the moment that log passed 2,147,483,648 entries. Measured on two live
    // anchors of the same domain: 2149645490 >> 1 = -1072660903 where the answer is 1074822745, while a proof from
    // two weeks earlier still verified — so the failure presented as a substrate change rather than an arithmetic one.
    //
    // The lesson is not 'use BigInt here'. It is that an index supplied by an EXTERNAL counter we do not control has
    // no ceiling we may assume, and arithmetic correct only below one is a dated charge with no alarm attached.
    // number | string | bigint are all accepted: a log serving a uint64 past 2^53 must send it as a string, and
    // refusing that would reinstate the same ceiling one power higher.
    if (!Array.isArray(hashes)) return false;
    let fn, sn;
    try { fn = BigInt(index); sn = BigInt(treeSize) - 1n; } catch { return false; }
    if (fn < 0n || sn < 0n || fn > sn) return false;
    let hash = leafHash;
    for (const sib of hashes.map(hexToBytes)) {
    if (fn === sn || (fn & 1n) === 1n) {               // right child, OR at the right edge → sibling on LEFT
      hash = sha256(Buffer.concat([Buffer.from([0x01]), sib, hash]));
      while (fn !== 0n && (fn & 1n) === 0n) { fn >>= 1n; sn >>= 1n; }   // climb past the right-edge run
    } else {                                            // left child → sibling on RIGHT
      hash = sha256(Buffer.concat([Buffer.from([0x01]), hash, sib]));
    }
    fn >>= 1n; sn >>= 1n;
    }
    return fn === 0n && hash.equals(hexToBytes(rootHash));
  } catch { return false; }
}

export function inclusionVerify(contentHash, proof) {
  try {
    // Round 204 (F.9.5-c.6) — the body reads from `proof.inclusion`, the NORMATIVE carrier, and the member is
    // `construction`. Before this it read `proof.anchor.inclusion.scheme`: a name of our own in a place of our own,
    // inside the SUBSTRATE's Locator, which §11.2 keeps separate from the membership proof on purpose. Nothing
    // published used that shape — measured across the estate, only this package and the operator's producer
    // mentioned it — so the move costs no reissue and removes the second place a construction could be declared.
    const inc = proof?.inclusion;
    if (!inc || inc.construction !== 'rfc6962-raw') return null;                // not ours — let the next connector try
    if (typeof contentHash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(contentHash)) return false;
    if (typeof proof.root !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(proof.root)) return false;
    // The leaf is bound to OUR content_hash by construction: leaf = SHA256(0x00 ‖ the 32 raw bytes of content_hash).
    // That binding is what makes this an inclusion proof FOR THIS DOCUMENT rather than for an arbitrary entry.
    const leaf = sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(contentHash.slice(7), 'hex')]));
    return verifyInclusion({ leafHash: leaf, index: inc.index, treeSize: inc.tree_size, hashes: inc.hashes, rootHash: proof.root.slice(7) });
  } catch { return false; }                                                     // untrusted input: a hostile getter is a refusal, never a throw
}
