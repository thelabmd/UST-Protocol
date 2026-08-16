// SPDX-License-Identifier: Apache-2.0
// @ust-protocol/rekor-verify — the opt-in Sigstore Rekor substrateVerify for UST anchors (#68 witness).
//
// A SECOND witness substrate next to Bitcoin (@ust-protocol/ots-verify). Rekor is a public append-only
// transparency log (Sigstore / Linux Foundation) — logging is seconds, not Bitcoin's hours, and it is
// independent of the publisher. Trade-off vs Bitcoin: faster + independent, but you trust the Rekor
// operator's LOG KEY (which co-signs its tree head); Bitcoin is trustless but slow.
//
// #69 Theme A1 (P0) — the anchor terminates at an EXTERNAL trust root, never a self-consistent object.
// An inclusion proof alone proves nothing: an attacker can fabricate a treeSize=1 tree whose rootHash is
// its own leaf. What binds the root to Rekor is the LOG's SIGNATURE over its checkpoint (signed tree head).
// So `final` requires ALL of: (1) the entry attests THIS root; (2) the inclusion path reaches proof.rootHash
// (RFC 6962); (3) the checkpoint is signed by Rekor's PINNED public key AND its root == proof.rootHash and
// size == proof.treeSize. Drop any leg → not final. The pinned key is the trust anchor (like a CA root);
// even the fallback API fetch is trustless because the signature — not the transport — decides.
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';

const REKOR = 'https://rekor.sigstore.dev';
// Pinned rekor.sigstore.dev log public key (EC P-256). This is a TRUST ANCHOR: it is NOT fetched from the
// same surface that serves the entry (that would be circular). Sigstore rotates keys via TUF; on a rotation
// this constant is updated (or pass your own via makeSubstrateVerify for a private Rekor). key hint c0d23d6a.
const REKOR_PUBKEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`;

const sha256 = (buf) => createHash('sha256').update(buf).digest();
const hexToBytes = (h) => Buffer.from(h.replace(/^sha256:/, ''), 'hex');

// RFC 6962 §2.1.1 inclusion-proof verification (canonical, incl. the right-edge while-shift — a naive
// left/right test is WRONG for a leaf near the tree's right edge, where fn==sn). leaf = SHA256(0x00||entry),
// interior = SHA256(0x01||left||right).
// round-236 (#173) — the RFC 6962 CONSTRUCTION connector moved to `@ust-protocol/rfc6962-verify`. It never had
// anything to do with rekor: it is SHA-256 and tree arithmetic over bytes the caller holds, and keeping it here
// made a consumer install a transparency-log client to verify a publisher anchored in BITCOIN. Re-exported so
// every installed consumer keeps working unchanged — the move is a packaging fix, not an API change.
// Imported AND re-exported: this package's own substrate check climbs the log's `inclusionProof` with the same
// RFC 6962 walk, so the function is needed as a local binding here, not only forwarded. That it serves BOTH axes —
// membership in a publisher's tree and membership in the LOG's tree — is the sharpest argument for it having its
// own package: it was never rekor's, and it was never only the construction connector's either.
import { verifyInclusion, inclusionVerify } from '@ust-protocol/rfc6962-verify';
export { verifyInclusion, inclusionVerify };

// Verify a Sigstore/Go signed-note checkpoint: the log's ECDSA signature over "origin\nsize\nroothash\n"
// (the note text up to the blank separator), and that the signed root/size match the inclusion proof's.
// Returns true ONLY if the PINNED log key signed a checkpoint committing to exactly proof.rootHash@treeSize.
export function verifyCheckpoint(checkpoint, expectedRootHex, expectedTreeSize, pubKey) {
  if (typeof checkpoint !== 'string' || checkpoint.indexOf('\n\n') < 0) return false;
  const lines = checkpoint.split('\n');
  if (lines.length < 5) return false;
  const origin = lines[0].split(' ')[0];                       // "rekor.sigstore.dev"
  if (lines[1] !== String(expectedTreeSize)) return false;     // signed size must match the proof's tree
  let rootHex; try { rootHex = Buffer.from(lines[2], 'base64').toString('hex'); } catch { return false; }
  if (rootHex !== expectedRootHex.replace(/^sha256:/, '')) return false;   // signed root must be the proof's
  const body = Buffer.from(checkpoint.slice(0, checkpoint.indexOf('\n\n') + 1), 'utf8'); // note text
  // signature block: one "— <keyname> <base64(keyhint4 || DER-ecdsa)>" line per cosigner; verify the LOG's.
  for (const line of checkpoint.slice(checkpoint.indexOf('\n\n') + 2).split('\n')) {
    const m = line.match(/^— (\S+) (\S+)$/);
    if (!m || m[1] !== origin) continue;                       // only the log-origin's own signature
    let sig; try { sig = Buffer.from(m[2], 'base64'); } catch { continue; }
    if (sig.length <= 4) continue;
    try { if (edVerify('sha256', body, pubKey, sig.subarray(4))) return true; } catch { /* wrong key/shape */ }
  }
  return false;
}

// #43 — this connector reaches a THIRD-PARTY service, so its requests carry a label. The shape is duplicated
// rather than imported ON PURPOSE: this package declares no dependencies, and taking one for a string would cost
// more than the copy. Agreement is held by `tools/user-agent-gate.mjs`, which reads the version from
// package.json — a copy whose agreement is CHECKED is a second witness, an unchecked one is drift.
const UA = 'ust/1.0 (ust-rekor-verify/1.0.0-rc.30; +https://github.com/thelabmd/UST-Protocol)';
const labelled = (impl) => (url, init = {}) => impl(url, { ...init, headers: { ...(init?.headers || {}), 'user-agent': UA } });
export function makeSubstrateVerify({ fetchImpl = labelled(fetch), api = REKOR, rekorPubKeyPem = REKOR_PUBKEY_PEM } = {}) {
  const pubKey = createPublicKey(rekorPubKeyPem);
  return async function substrateVerify(anchor, root) {
    // totality (round-46 self-audit) — the anchor is UNTRUSTED: read it behind a guard so a hostile getter/Proxy declines (null →
    // the router tries the next plugin), never a host throw. The integrated path passes an inert admitted proof; this covers a direct call.
    let a;
    try { a = anchor?.substrate === 'rekor' ? anchor : (anchor?.anchor?.substrate === 'rekor' ? anchor.anchor : null); } catch { return null; }
    if (!a || typeof root !== 'string') return null;   // not ours → let the router try the next plugin

    let proof = a.inclusionProof, integratedTime = a.integratedTime, bodyB64 = a.body;
    // fetch the entry if the anchor only carries a pointer (logIndex) — the API is a fallback; the pinned-key
    // signature (below) is what decides, so a MITM'd API response cannot forge finality.
    if ((!proof || !bodyB64) && (a.logIndex != null || a.uuid)) {
      // round-46 self-audit — the uuid/logIndex come from the UNTRUSTED anchor and are interpolated into the fetch URL. The host is
      // fixed by `api` (a uuid in the path cannot redirect hosts) and the pinned-key signature below is the finality decider, so this
      // is not exploitable — but an unvalidated value in a URL is an audit-flag and defense-in-depth: validate the FORMAT (a rekor
      // entry UUID is 64–80 hex; logIndex a non-negative integer) before constructing the URL, else decline.
      const uuidOk = a.uuid == null || /^[0-9a-f]{64,80}$/.test(String(a.uuid));
      const idxOk = a.logIndex == null || (Number.isInteger(a.logIndex) && a.logIndex >= 0);
      if (!uuidOk || !idxOk) return { final: false, time: 'unproven', reason: 'proof-absent' };
      try {
        const url = a.uuid ? `${api}/api/v1/log/entries/${a.uuid}` : `${api}/api/v1/log/entries?logIndex=${a.logIndex}`;
        const r = await fetchImpl(url, { signal: AbortSignal.timeout(10000) });
        if (!r.ok) return { final: false, time: 'unproven', reason: 'substrate-unreachable' };
        const j = await r.json();
        const entry = Object.values(j)[0];
        proof = proof || entry?.verification?.inclusionProof;
        integratedTime = integratedTime || entry?.integratedTime;
        bodyB64 = bodyB64 || entry?.body;
      } catch { return { final: false, time: 'unproven', reason: 'substrate-unreachable' }; }
    }
    if (!proof || !bodyB64) return { final: false, time: 'unproven', reason: 'proof-absent' };

    // (1) the logged entry MUST attest THIS root, checked by the EXACT hashedrekord schema — NOT a substring
    // scan of the body (#71: a validly-signed entry that merely CONTAINS the hash in some other field, e.g. a
    // comment, would otherwise pass). Convention (§17 rekor Locator): the artifact logged is the root's hex
    // string (utf8); Rekor stores sha256(artifact) at spec.data.hash.value with algorithm sha256.
    const rootHex = root.replace(/^sha256:/, '');
    const artifactHash = createHash('sha256').update(Buffer.from(rootHex, 'utf8')).digest('hex');
    // EVERY REFUSAL BELOW IS STATED, NOT A DECLINE, and every one carries a reason from REGISTRY.anchorRefusalReasons.
    //
    // By this line the anchor has already NAMED `rekor` — the guard at the top of this function let nothing else
    // through. So no later plugin can answer for it, and `null` sends the router looking for one anyway; the
    // consumer is then told the substrate was unreachable when this connector had just told it claim is not proof.
    // The reason is a slug because the core admits it as one: a not-ours module may not write prose into a verdict.
    //
    // Until 2026-08-07 all of them returned `null`; three then became stated, and SIX others — the malformed
    // pointer, the two fetch failures, the absent proof, and the two conjuncts below — kept a bare `false`. Those two
    // conjuncts are exactly where the #155 defect lived, and a caller could not tell them apart from a network
    // outage. F.5.1e: a conjunction refuses by NAMING its conjunct, because the reasons differ in who can act.
    let entry;
    try { entry = JSON.parse(Buffer.from(bodyB64, 'base64').toString('utf8')); }
    catch { return { final: false, time: 'unproven', reason: 'unreadable-entry' }; }
    if (entry?.kind !== 'hashedrekord') return { final: false, time: 'unproven', reason: 'unsupported-proof-form' };
    const h = entry?.spec?.data?.hash;
    if (!h || h.algorithm !== 'sha256' || h.value !== artifactHash) {
      return { final: false, time: 'unproven', reason: 'entry-attests-another-root' };
    }

    // (2) the inclusion path reaches proof.rootHash (RFC 6962).
    const leafHash = sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(bodyB64, 'base64')]));
    if (!verifyInclusion({ leafHash, index: proof.logIndex, treeSize: proof.treeSize, hashes: proof.hashes || [], rootHash: proof.rootHash }))
      return { final: false, time: 'unproven', reason: 'inclusion-failed' };

    // (3) #69 A1 — proof.rootHash MUST be a root the LOG signed. Without a valid checkpoint signature the
    // inclusion proof is only a self-consistent Merkle object (a fabricated treeSize=1 tree passes (2)).
    if (!verifyCheckpoint(proof.checkpoint, proof.rootHash, proof.treeSize, pubKey))
      return { final: false, time: 'unproven', reason: 'checkpoint-unsigned' };

    return { final: true, time: integratedTime ? new Date(integratedTime * 1000).toISOString().slice(0, 19) + 'Z' : 'rekor-logged', log_index: String(proof.logIndex) };
  };
}

// P1-06 — emit a TYPED, capability-bearing VerifiedEvidence from a FINAL Rekor result, consumed by the core's
// freshness derivation (transparency-log ⇒ inclusion+consistency+order over the SAME log, per EVIDENCE_CAPS; NOT
// non-membership/uniqueness). A non-final result yields null. The log index is the within-log order coordinate.
export function toVerifiedEvidence(subject, result, source_id = 'rekor') {
  if (!result || result.final !== true || result.log_index === undefined) return null;
  const isoZ = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
  return { proof_kind: 'transparency-log', subject, source_id,
    facts: { substrate: 'rekor', position: String(result.log_index), ...(isoZ.test(result.time || '') ? { not_before: result.time } : {}) } };
}

export const substrateVerify = makeSubstrateVerify();

// ─── §11.3/#95 INCLUSION connector. Distinct from `substrateVerify` above, and the distinction is the whole point: that
// one proves the anchored ROOT was logged (finality, and it binds the logged entry to OUR root by the hashedrekord
// schema). THIS one answers a different question — is `content_hash` a member of the leaf-set the root commits — and it
// is the PUBLISHER's tree, not rekor's.
//
// So this connector claims a proof only when the publisher has declared its membership tree to be RFC 6962 over raw
// digests, by carrying `anchor.inclusion: { scheme: "rfc6962-raw", index, tree_size, hashes[] }`. Absent that field it
// returns null — "not mine" — and the router falls through to whatever the caller has, ultimately the bundled walk.
// It NEVER guesses a scheme: a wrong leaf convention would verify a proof for somebody else's entry, which is the
// proof-substitution hole this repo is built to refuse.
