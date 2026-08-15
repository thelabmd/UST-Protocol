// A self-contained OpenTimestamps codec — parse, serialize, and complete a proof, with no dependency.
//
// WHY THIS EXISTS. Reading an `.ots` file used to require the `opentimestamps` package, and that package pulls
// `bitcore-lib`, `request`/`request-promise` (deprecated since 2020) and `fs@0.0.1-security` — a placeholder
// published under a squatted name. Measured 2026-08-07 on a clean install: 12 advisories, 2 of them critical.
// Every consumer of an anchored document was being asked to accept that in order to read a binary format that
// fits on two screens, and downstream scanners flag the dependent package for it.
//
// The format is small and stable. The dependency was not.
// CLOSED 2026-08-07 by REV 65 — this file is the replacement, the peer declaration is gone, and
// `tools/ots-codec-gate.mjs` derives the import roster from source so the removal cannot quietly undo itself.
//
// WHAT IS AND IS NOT HERE. This reads and completes timestamps; it does not CREATE them. Stamping needs a
// nonce, a Merkle aggregation and a submission round-trip — that is publisher work, it runs where the operator
// runs, and it has no business in the package a verifier installs.
//
// FAIL CLOSED ON THE UNKNOWN. An operation this codec does not implement REFUSES rather than being skipped.
// A skipped operation would silently change the message the rest of the proof is computed over, and the
// verdict would then be about a digest nobody committed to. There is no safe way to ignore a byte here.
//
// Hashing follows the core: `node:crypto`, synchronous, zero dependencies. WebCrypto would have been the more
// portable choice in isolation, but the neighbouring modules do it this way and a second mechanism for one
// hash is a divergence with no buyer.

import { createHash } from 'node:crypto';

const MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex');
const MAJOR = 0x01;

/** §OTS attestation tags — 8 bytes each, and the only three the wire defines today. */
export const TAG_PENDING = Buffer.from('83dfe30d2ef90c8e', 'hex');
export const TAG_BITCOIN = Buffer.from('0588960d73d71901', 'hex');
export const TAG_LITECOIN = Buffer.from('06869a0d73d71b45', 'hex');

const sha256 = (b) => createHash('sha256').update(b).digest();
const ripemd160 = (b) => createHash('ripemd160').update(b).digest();
const sha1 = (b) => createHash('sha1').update(b).digest();

/**
 * Unary operations, keyed by wire tag. A hash op takes the message and returns the new one.
 *
 * `0xf3` (reverse) and `0xf2` (hexlify) are DELIBERATELY ABSENT: they exist in the format's history, no
 * calendar emits them, and implementing an operation nobody produces means shipping an untested path through
 * the one function whose correctness the whole proof rests on. Meeting one refuses, loudly, with its tag.
 */
const UNARY = { 0x08: sha256, 0x02: ripemd160, 0x03: sha1 };

class Reader {
  constructor(buf) { this.b = buf; this.p = 0; }
  u8() { if (this.p >= this.b.length) throw new Error('ots: truncated'); return this.b[this.p++]; }
  take(n) {
    if (n < 0 || this.p + n > this.b.length) throw new Error('ots: truncated');
    const out = this.b.subarray(this.p, this.p + n); this.p += n; return out;
  }
  /** Base-128 varint, little-endian groups. Bounded: a length that cannot address real bytes is malformed. */
  varint() {
    let r = 0, shift = 0;
    for (;;) {
      const b = this.u8();
      r += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) break;
      shift += 7;
      if (shift > 63) throw new Error('ots: varint too long');
    }
    return r;
  }
  varbytes() { return this.take(this.varint()); }
}

function writeVarint(n) {
  const out = [];
  for (;;) { const b = n % 128; n = Math.floor(n / 128); out.push(n ? b | 0x80 : b); if (!n) break; }
  return Buffer.from(out);
}
const writeVarbytes = (b) => Buffer.concat([writeVarint(b.length), Buffer.from(b)]);

/**
 * The parsed shape.
 *
 *   node  = { msg, steps: [step] }                  the message at this point, and what follows it
 *   step  = { kind: 'attest', tag, payload }
 *         | { kind: 'op', tag, arg, next: node }
 *
 * `msg` is carried on every node because it is what an attestation attests and what the next operation
 * consumes. Recomputing it at read time is what makes a spliced-in upgrade verifiable rather than trusted.
 */
function readNode(r, msg) {
  const steps = [];
  let tag = r.u8();
  while (tag === 0xff) { steps.push(readStep(r, msg)); tag = r.u8(); }
  steps.push(readStep(r, msg, tag));
  return { msg, steps };
}

function readStep(r, msg, tag = r.u8()) {
  if (tag === 0x00) {
    const at = Buffer.from(r.take(8));
    const payload = Buffer.from(r.varbytes());
    return { kind: 'attest', tag: at, payload };
  }
  if (tag === 0xf0 || tag === 0xf1) {
    const arg = Buffer.from(r.varbytes());
    const next = tag === 0xf0 ? Buffer.concat([msg, arg]) : Buffer.concat([arg, msg]);
    return { kind: 'op', tag, arg, next: readNode(r, next) };
  }
  const fn = UNARY[tag];
  if (!fn) throw new Error(`ots: operation 0x${tag.toString(16)} is not implemented — refusing rather than skipping`);
  return { kind: 'op', tag, arg: null, next: readNode(r, fn(msg)) };
}

function writeNode(node) {
  const parts = [];
  node.steps.forEach((s, i) => {
    if (i < node.steps.length - 1) parts.push(Buffer.from([0xff]));
    parts.push(writeStep(s));
  });
  return Buffer.concat(parts);
}

function writeStep(s) {
  if (s.kind === 'attest') return Buffer.concat([Buffer.from([0x00]), s.tag, writeVarbytes(s.payload)]);
  const head = Buffer.from([s.tag]);
  const arg = s.arg ? writeVarbytes(s.arg) : Buffer.alloc(0);
  return Buffer.concat([head, arg, writeNode(s.next)]);
}

/** Parse a detached `.ots` file. Returns `{ hashOp, digest, root }`; throws on anything it cannot represent. */
export function parseOts(bytes) {
  const buf = Buffer.from(bytes);
  const r = new Reader(buf);
  if (!Buffer.from(r.take(MAGIC.length)).equals(MAGIC)) throw new Error('ots: not a detached timestamp file');
  const major = r.u8();
  if (major !== MAJOR) throw new Error(`ots: unsupported major version ${major}`);
  const hashOp = r.u8();
  const size = { 0x08: 32, 0x02: 20, 0x03: 20 }[hashOp];
  if (!size) throw new Error(`ots: unsupported file-hash op 0x${hashOp.toString(16)}`);
  const digest = Buffer.from(r.take(size));
  const root = readNode(r, digest);
  if (r.p !== buf.length) throw new Error(`ots: ${buf.length - r.p} trailing byte(s) — refusing a proof I do not fully account for`);
  return { hashOp, digest, root };
}

/** Serialize back to `.ots` bytes. Round-trips byte-for-byte — that equality is the codec's own test. */
export function serializeOts({ hashOp, digest, root }) {
  return Buffer.concat([MAGIC, Buffer.from([MAJOR, hashOp]), Buffer.from(digest), writeNode(root)]);
}

/** Walk every node, yielding `{ msg, step }` for each attestation reached. */
export function* attestations(node) {
  for (const s of node.steps) {
    if (s.kind === 'attest') yield { msg: node.msg, step: s };
    else yield* attestations(s.next);
  }
}

/** Bitcoin attestations, as `{ height, msg }` — `msg` is the block's merkle root in internal byte order. */
export function bitcoinAttestations(parsed) {
  const out = [];
  for (const { msg, step } of attestations(parsed.root)) {
    if (!step.tag.equals(TAG_BITCOIN)) continue;
    out.push({ height: new Reader(step.payload).varint(), msg: Buffer.from(msg) });
  }
  return out;
}

const URI_OK = /^[A-Za-z0-9\-._/:]{1,1000}$/;

/** Pending attestations, as `{ uri, msg }`. A URI outside the format's own character set is refused. */
export function pendingAttestations(parsed) {
  const out = [];
  for (const { msg, step } of attestations(parsed.root)) {
    if (!step.tag.equals(TAG_PENDING)) continue;
    const uri = new Reader(step.payload).varbytes().toString('ascii');
    if (!URI_OK.test(uri)) throw new Error('ots: pending attestation carries a URI outside the allowed set');
    out.push({ uri, msg: Buffer.from(msg) });
  }
  return out;
}

/** `true` once any attestation names a block — the proof needs no calendar to be read. */
export const isComplete = (parsed) => bitcoinAttestations(parsed).length > 0;

/**
 * Complete a pending proof from its calendars.
 *
 * THIS IS PUBLISHER WORK, and it is exported so the publisher can do it — NOT so a verifier can do it on the
 * publisher's behalf. A verifier that fetches the missing half of someone else's evidence leaks which digest
 * it is checking, makes its verdict depend on a remote service, and hides a stalled publisher from everyone:
 * each consumer silently patches the gap and no one ever sees the failure. `pending` is a true answer; turning
 * it into `final` by calling out is a different act with a different name.
 *
 * THE RESULT IS A CANDIDATE, NOT A VERIFIED PROOF, and the signature says so: the input is left untouched and
 * a new structure is returned. Measured 2026-08-07, because an earlier draft of this very comment claimed a
 * protection that did not exist — a WELL-FORMED continuation belonging to a DIFFERENT commitment splices in
 * cleanly. It has to: the reply is a path, the codec has no way to know which block a path should reach, and
 * finding out requires the network.
 *
 * What that costs depends entirely on what the caller does next. The spliced path computes a merkle root from
 * OUR message, so a foreign reply yields a root the real block does not carry, and `substrateVerify` refuses
 * it against the explorers. That is the actual guard, and it lives one layer up.
 *
 * So: **corroborate before you persist.** A publisher writing a candidate straight into an append-only store
 * writes a proof it never checked, into a slot it cannot take back.
 *
 * The reply is APPENDED beside the pending attestation rather than replacing it — the pending record stays
 * true, and the completed path joins it.
 * CLOSED 2026-08-07 in the same edit that measured it — the signature carries the finding: `candidate`,
 * `corroborated: false`, and an untouched input, with a test asserting the foreign reply DOES splice.
 */
// #43 — the CALENDAR path reaches third-party OTS servers, and it is the highest-volume outbound call this tree
// makes: an operator upgrading pending proofs hits it once per pending anchor. It was found by the user-agent
// gate rather than by the sweep that preceded it — the sweep enumerated packages, and this is a second module
// inside one that was already counted.
// This is the LEAF of the package (`index.mjs` imports it, never the reverse), so the package's one label lives
// here and is imported upward. The copy this package does keep is the one ACROSS packages, where taking a
// dependency for a string would cost more than the copy; a second copy INSIDE one module graph buys nothing and
// drifts on the next rc.
export const UA = 'ust/1.0 (ust-ots-verify/1.0.0-rc.35; +https://github.com/thelabmd/UST-Protocol)';
export const labelled = (impl) => (url, init = {}) => impl(url, { ...init, headers: { ...(init?.headers || {}), 'user-agent': UA } });
const labelledCal = labelled(fetch);
export async function upgradeOts(input, { fetchImpl = labelledCal, timeoutMs = 15_000, maxBytes = 10_000 } = {}) {
  // Deep copy: an upgrade that mutated its argument would leave a caller holding a half-spliced proof after a
  // refusal, with no way to tell it from the one it handed in.
  const parsed = parseOts(serializeOts(input));
  let added = 0;
  const visit = async (node) => {
    for (const s of node.steps) if (s.kind === 'op') await visit(s.next);
    const pending = node.steps.filter((s) => s.kind === 'attest' && s.tag.equals(TAG_PENDING));
    if (!pending.length || node.steps.some((s) => s.kind === 'attest' && s.tag.equals(TAG_BITCOIN))) return;
    for (const p of pending) {
      const uri = new Reader(p.payload).varbytes().toString('ascii');
      if (!URI_OK.test(uri)) continue;
      let body;
      try {
        const r = await fetchImpl(`${uri}/timestamp/${Buffer.from(node.msg).toString('hex')}`,
          { headers: { accept: 'application/vnd.opentimestamps.v1' }, signal: AbortSignal.timeout(timeoutMs) });
        if (!r.ok) continue;                                   // 404 = the calendar has nothing yet; not an error
        const bytes = Buffer.from(await r.arrayBuffer());
        if (bytes.length > maxBytes) continue;                 // a calendar is not allowed to hand us a payload
        body = bytes;
      } catch { continue; }                                    // unreachable calendar leaves the proof pending
      // Parsed against OUR message: the ops are replayed from the commitment we hold. This makes the reply
      // STRUCTURALLY ours; it does not make it TRUE — see the note above.
      let reply;
      try { reply = readNode(new Reader(body), node.msg); } catch { continue; }
      node.steps.push(...reply.steps);
      added += reply.steps.length;
    }
  };
  await visit(parsed.root);
  return { candidate: parsed, added, corroborated: false };
}
