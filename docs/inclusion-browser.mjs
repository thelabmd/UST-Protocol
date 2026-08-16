// SPDX-License-Identifier: Apache-2.0
// The CONSTRUCTION connector for the browser — the `rfc6962-raw` membership walk, supplied to the core as
// `opts.inclusionVerify`. It is the browser twin of `@ust-protocol/rfc6962-verify`, and it exists as a separate
// file for the same reason that package does: membership in a publisher's tree and commitment of that tree to
// the outside world are TWO independent proofs (§11.2), answered by two independent faculties.
//
// It is ASYNC, and cannot be otherwise: WebCrypto's digest returns a promise. Until round 236 the core's
// inclusion seam accepted only a synchronous connector and read a promise as `inclusion: false` — a document
// called forged because the reader's own connector was async — so no browser could supply one at all. The async
// door (`verifyAsync` / `resolveByDiscovery`) now resolves the seam before deciding, which is what makes this
// file possible rather than clever.
//
// The climb itself is NOT re-implemented here: `rekorInclusion` in ust-resolve.mjs is already a correct RFC 6962
// walk over unbounded (BigInt) indices, and `unbounded-index-gate` drives it against the Node connector on the
// same paths above 2^31 and 2^53. A second copy would be a second thing to keep right.
import { rekorInclusion } from './ust-resolve.mjs';

const HASHREF = /^sha256:[0-9a-f]{64}$/;
const hexToU8 = (h) => { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16); return b; };

/**
 * `inclusionVerify(contentHash, proof)` — the core's construction seam.
 *
 * Returns `null` for a proof declaring any other construction: the core's router then falls through to the next
 * connector or to its own bundled walk, so this is safe to pass unconditionally. Returns a strict boolean
 * otherwise, and never throws — untrusted input is a refusal, never a host throw (trust-boundary law UST-5tm).
 */
export async function inclusionVerify(contentHash, proof) {
  try {
    const inc = proof?.inclusion;
    if (!inc || inc.construction !== 'rfc6962-raw') return null;            // not ours — let the next connector try
    if (typeof contentHash !== 'string' || !HASHREF.test(contentHash)) return false;
    if (typeof proof.root !== 'string' || !HASHREF.test(proof.root)) return false;
    // The leaf binds the proof to THIS document by construction: leaf = SHA256(0x00 ‖ the 32 raw bytes of content_hash).
    const raw = hexToU8(contentHash.slice(7));
    const pre = new Uint8Array(1 + raw.length); pre[0] = 0x00; pre.set(raw, 1);
    const leafHash = new Uint8Array(await crypto.subtle.digest('SHA-256', pre));
    return await rekorInclusion({ leafHash, index: inc.index, treeSize: inc.tree_size, hashes: inc.hashes, rootHash: proof.root.slice(7) });
  } catch { return false; }
}
