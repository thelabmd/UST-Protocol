// SPDX-License-Identifier: Apache-2.0
// @ust-protocol/rekor-verify — the opt-in Sigstore Rekor substrateVerify for UST anchors (#68 witness).
//
// A SECOND witness substrate next to Bitcoin (@ust-protocol/ots-verify). Rekor is a public append-only
// transparency log (Sigstore / Linux Foundation) — logging is seconds, not Bitcoin's hours, and it is
// independent of the publisher. Trade-off vs Bitcoin: faster + independent, but you trust the Rekor
// operator's log (its own witnesses co-sign the tree head); Bitcoin is trustless but slow. A verifier
// can accept BOTH via ust-protocol's combineSubstrates — each answers the same question ("is this root
// committed & final?") in its own dialect (§17 substrate registry).
//
// substrateVerify(anchor, root) → { final, time } | null
//   anchor = { substrate:'rekor', logIndex, treeID?, inclusionProof:{ logIndex, rootHash, treeSize,
//              hashes:[...], checkpoint }, integratedTime }
//   · null  → not a rekor anchor (router delegates onward) OR the entry does not attest THIS root
//   · final → the root is included in the Rekor log AND the inclusion proof verifies to the tree root
//   The proof is SELF-CONTAINED (embedded at anchor time); we re-verify the Merkle path — the Rekor API
//   is only a fallback fetch, the math is what decides (claim ≠ proof, same discipline as everywhere).
import { createHash } from 'node:crypto';

const REKOR = 'https://rekor.sigstore.dev';
const sha256 = (buf) => createHash('sha256').update(buf).digest();
const hexToBytes = (h) => Buffer.from(h.replace(/^sha256:/, ''), 'hex');

// RFC 6962 §2.1.1 inclusion-proof verification: recompute the tree root from the leaf + audit path.
// leaf hash = SHA256(0x00 || entry_bytes); interior = SHA256(0x01 || left || right).
function verifyInclusion({ leafHash, index, treeSize, hashes, rootHash }) {
  if (index >= treeSize || index < 0) return false;
  let hash = leafHash, fn = index, sn = treeSize - 1, i = 0;
  for (const sib of hashes.map(hexToBytes)) {
    if (fn === sn && (fn & 1) === 0) { // last node at this level and left child → carry up
      hash = sha256(Buffer.concat([Buffer.from([0x01]), hash, sib]));
    } else if ((fn & 1) === 1) {       // right child
      hash = sha256(Buffer.concat([Buffer.from([0x01]), sib, hash]));
    } else {                            // left child
      hash = sha256(Buffer.concat([Buffer.from([0x01]), hash, sib]));
    }
    fn >>= 1; sn >>= 1; i++;
  }
  return hash.equals(hexToBytes(rootHash));
}

export function makeSubstrateVerify({ fetchImpl = fetch, api = REKOR } = {}) {
  return async function substrateVerify(anchor, root) {
    const a = anchor?.substrate === 'rekor' ? anchor : (anchor?.anchor?.substrate === 'rekor' ? anchor.anchor : null);
    if (!a || typeof root !== 'string') return null;   // not ours → let the router try the next plugin

    let proof = a.inclusionProof, integratedTime = a.integratedTime, bodyB64 = a.body;
    // fetch the entry if the anchor only carries a pointer (logIndex) — the API is a fallback, the proof decides
    if ((!proof || !bodyB64) && (a.logIndex != null || a.uuid)) {
      try {
        const url = a.uuid ? `${api}/api/v1/log/entries/${a.uuid}` : `${api}/api/v1/log/entries?logIndex=${a.logIndex}`;
        const r = await fetchImpl(url, { signal: AbortSignal.timeout(10000) });
        if (!r.ok) return { final: false, time: 'unproven' };
        const j = await r.json();
        const entry = Object.values(j)[0];
        proof = proof || entry?.verification?.inclusionProof;
        integratedTime = integratedTime || entry?.integratedTime;
        bodyB64 = bodyB64 || entry?.body;
      } catch { return { final: false, time: 'unproven' }; }
    }
    if (!proof || !bodyB64) return { final: false, time: 'unproven' };

    // the logged entry MUST attest THIS root — the genesis leaf-root must appear in the entry body
    let body; try { body = Buffer.from(bodyB64, 'base64').toString('utf8'); } catch { return null; }
    const rootHex = root.replace(/^sha256:/, '');
    if (!body.includes(rootHex)) return null;   // this Rekor entry is about someone else's digest

    const leafHash = sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(bodyB64, 'base64')]));
    const ok = verifyInclusion({ leafHash, index: proof.logIndex, treeSize: proof.treeSize, hashes: proof.hashes || [], rootHash: proof.rootHash });
    if (!ok) return { final: false, time: 'unproven' };
    return { final: true, time: integratedTime ? new Date(integratedTime * 1000).toISOString().slice(0, 19) + 'Z' : 'rekor-logged' };
  };
}

export const substrateVerify = makeSubstrateVerify();
