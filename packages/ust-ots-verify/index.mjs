// SPDX-License-Identifier: Apache-2.0
// @ust-protocol/ots-verify — the OPT-IN Bitcoin substrateVerify for UST anchors (#68 Ф1b).
//
// WHY A SEPARATE PACKAGE: the zero-dependency reference verifier (ust-protocol) must never embed a
// blockchain / the heavy opentimestamps lib — a verifier that carries a Bitcoin node is not portable.
// resolveByDiscovery / verifyAnchor take `substrateVerify` as an OPTIONAL injection: without it, an
// anchor is honestly `unproven` (→ "HIGH pending"); WITH this package the anchor is cross-checked against
// Bitcoin. An integrator that wants the cross-check installs this; nobody is forced to.
//
// substrateVerify(anchor, root) → { final, time } | null  — the exact shape verifyAnchor expects:
//   · final:true  → the root is committed in a Bitcoin block (≥ the lib's confirmation view)
//   · final:false → the .ots is still calendar-pending (no Bitcoin attestation yet)
//   · null        → the .ots does not attest THIS root (wrong digest) → treated as not-verified
import { createRequire } from 'node:module';
// the lib ships a broken package.json main; createRequire sidesteps bundlers (proven in noosphere-anchor).
const OTS = createRequire(import.meta.url)('opentimestamps');

const hexToBytes = (hex) => { const h = hex.replace(/^sha256:/, ''); const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; };
const bytesEq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// Extract the Bitcoin block height (if any) from a complete timestamp's attestations.
function bitcoinHeight(det) {
  try {
    for (const [, atts] of det.timestamp.allAttestations()) {
      for (const a of (Array.isArray(atts) ? atts : [atts])) {
        if (a && (a._type === 'BitcoinBlockHeaderAttestation' || a.constructor?.name?.includes('Bitcoin')) && typeof a.height === 'number') return a.height;
      }
    }
  } catch { /* shape drift — fall through */ }
  return null;
}

export function makeSubstrateVerify({ upgrade = true } = {}) {
  return async function substrateVerify(anchor, root) {
    // handle ONLY bitcoin-ots — return null for any other substrate so a multi-substrate router
    // (ust-protocol combineSubstrates) can delegate to the next plugin.
    const sub = anchor?.substrate ?? anchor?.anchor?.substrate;
    if (sub && sub !== 'bitcoin-ots') return null;
    const otsB64 = anchor?.ots ?? anchor?.anchor?.ots;
    if (!otsB64 || typeof root !== 'string') return null;
    let det;
    try { det = OTS.DetachedTimestampFile.deserialize(Uint8Array.from(Buffer.from(otsB64, 'base64'))); }
    catch { return null; }
    // the .ots MUST attest THIS root — otherwise it proves nothing about our genesis
    if (!bytesEq(new Uint8Array(det.timestamp.msg), hexToBytes(root))) return null;
    if (!det.timestamp.isTimestampComplete() && upgrade) {
      try { await OTS.upgrade(det); } catch { /* calendar unreachable → stays pending */ }
    }
    if (!det.timestamp.isTimestampComplete()) return { final: false, time: 'unproven' };
    const h = bitcoinHeight(det);
    return { final: true, time: h ? 'bitcoin-block-' + h : 'anchored' };
  };
}

// Convenience default (upgrade-on-verify). Pass to resolveByDiscovery/verifyAnchor as `substrateVerify`.
export const substrateVerify = makeSubstrateVerify();
