// SPDX-License-Identifier: Apache-2.0
// @assurance 4 canfail:no — our assertions against our own codec. Deliberately the weakest grade: the fixture is
// real calendar output but it is PINNED, so nothing here consults the world at run time. What keeps it honest is
// that the splice limitation is asserted POSITIVELY — a foreign well-formed reply DOES splice — so the suite
// cannot drift into claiming a protection the codec does not provide.
// The codec's own tests. Fixtures are REAL calendar output, not something shaped to fit the parser: a
// hand-built proof would exercise the encoder's idea of the format rather than the format.
//
// The load-bearing test is the ROUND TRIP. A parser that reads a file into a structure can be wrong in ways
// no field-by-field assertion catches — a dropped branch, a misread length, an operation silently skipped —
// and every one of those changes the message the rest of the proof is computed over. Serializing back and
// demanding byte equality asks the one question that covers them all: did you account for every byte?

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseOts, serializeOts, bitcoinAttestations, pendingAttestations, isComplete, upgradeOts,
  TAG_BITCOIN, TAG_PENDING,
} from './ots-codec.mjs';

/** A real, still-pending proof from a public calendar: header, digest, one pending attestation. */
const PENDING_HEX =
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294010849fea448c53f63fa2fe51e' +
  'c1b7e3a9788594141c2e808a92e8b45e875e1be670f008a9c65a01cb60f72308f020e104b06129d714a759fa' +
  '758e3ff67fee30671e2151cecaa1f75b2e23f923cfa608f02080054764731e53a05bb27d0e2e5ff7e4113d8b' +
  '0ef62ea962ee5acb822c6b28bc08f01029683d4f460be55cee29dcb279d8547e08f0209292f396288b096632' +
  '1fd27df778c659c7ad039d0aa8d0d3e7a436b163e6a8bf08f1046a75910ef00888587f6a60dd9e800083dfe3' +
  '0d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374' +
  '616d70732e6f7267';

const PENDING = Buffer.from(PENDING_HEX, 'hex');

/** Build a proof the encoder can produce, so structural cases do not depend on a network fixture. */
function synthetic({ withBitcoin = false, branches = 1 } = {}) {
  const digest = Buffer.alloc(32, 7);
  const steps = [];
  for (let i = 0; i < branches; i++) {
    steps.push({
      kind: 'op', tag: 0xf0, arg: Buffer.from([i]),
      next: {
        msg: Buffer.concat([digest, Buffer.from([i])]),
        steps: [withBitcoin
          ? { kind: 'attest', tag: TAG_BITCOIN, payload: Buffer.from([0x96, 0x0f]) }
          : { kind: 'attest', tag: TAG_PENDING, payload: Buffer.concat([Buffer.from([21]), Buffer.from('https://cal.example/x')]) }],
      },
    });
  }
  return { hashOp: 0x08, digest, root: { msg: digest, steps } };
}

test('round trip is byte-identical — the question that covers every misread byte', () => {
  const bytes = serializeOts(synthetic({ branches: 3 }));
  assert.ok(serializeOts(parseOts(bytes)).equals(bytes));
});

test('round trip holds for a multi-branch proof, not only a linear one', () => {
  // The 0xff separator is the format's easiest thing to lose: with one branch it never appears.
  const one = serializeOts(synthetic({ branches: 1 }));
  const many = serializeOts(synthetic({ branches: 4 }));
  assert.equal(one.includes(0xff), false, 'a single branch writes no separator');
  assert.ok(many.includes(0xff), 'several branches must');
  assert.ok(serializeOts(parseOts(many)).equals(many));
});

test('the stamped digest is read, and it is what an anchor is checked against', () => {
  const p = parseOts(serializeOts(synthetic()));
  assert.equal(p.digest.toString('hex'), '07'.repeat(32));
});

test('a Bitcoin attestation yields its height and the message it attests', () => {
  const p = parseOts(serializeOts(synthetic({ withBitcoin: true })));
  const btc = bitcoinAttestations(p);
  assert.equal(btc.length, 1);
  assert.equal(btc[0].height, 1942);                       // varint 0x96 0x0f
  assert.equal(isComplete(p), true);
});

test('a pending attestation yields its calendar, and pending is NOT complete', () => {
  const p = parseOts(serializeOts(synthetic()));
  assert.deepEqual(pendingAttestations(p).map((x) => x.uri), ['https://cal.example/x']);
  assert.equal(isComplete(p), false, 'pending is a true answer, not a lesser final');
});

test('refuses a truncated file rather than reporting what it managed to read', () => {
  const bytes = serializeOts(synthetic({ withBitcoin: true }));
  assert.throws(() => parseOts(bytes.subarray(0, bytes.length - 3)), /truncated/);
});

test('refuses trailing bytes — a proof it does not fully account for is not a proof', () => {
  const bytes = serializeOts(synthetic());
  assert.throws(() => parseOts(Buffer.concat([bytes, Buffer.from([0])])), /trailing/);
});

test('refuses a foreign magic and an unknown major version', () => {
  const bytes = serializeOts(synthetic());
  const badMagic = Buffer.from(bytes); badMagic[3] ^= 0xff;
  assert.throws(() => parseOts(badMagic), /not a detached timestamp file/);
  const badMajor = Buffer.from(bytes); badMajor[31] = 2;
  assert.throws(() => parseOts(badMajor), /major version 2/);
});

test('an unimplemented operation REFUSES — skipping it would change the message silently', () => {
  const bytes = Buffer.from(serializeOts(synthetic()));
  bytes[65] = 0x7e;                                        // first byte after header+digest: the branch op
  assert.throws(() => parseOts(bytes), /not implemented/);
});

test('a real pending proof from a calendar parses and round-trips', () => {
  const p = parseOts(PENDING);
  assert.equal(p.digest.toString('hex'), '49fea448c53f63fa2fe51ec1b7e3a9788594141c2e808a92e8b45e875e1be670');
  assert.equal(isComplete(p), false);
  assert.ok(serializeOts(p).equals(PENDING));
});

test('upgrade leaves its INPUT untouched and returns a candidate that says it is one', async () => {
  const input = parseOts(serializeOts(synthetic()));
  const reply = serializeOts(synthetic({ withBitcoin: true })).subarray(65);
  const out = await upgradeOts(input, { fetchImpl: async () => new Response(reply, { status: 200 }) });

  assert.equal(isComplete(input), false, 'the caller still holds exactly what it handed in');
  assert.equal(out.corroborated, false, 'a fetched path is a candidate until an explorer says otherwise');
  assert.equal(isComplete(out.candidate), true);
});

test('a WELL-FORMED reply for another commitment splices — and that is why a candidate must be corroborated', async () => {
  // Measured, not assumed: the codec cannot know which block a path should reach, so it cannot refuse this.
  // The guard is one layer up, in the explorer comparison. Pinning the limitation keeps a future reader from
  // trusting the splice for a protection it does not provide.
  const input = parseOts(serializeOts(synthetic()));
  const foreign = serializeOts(synthetic({ withBitcoin: true, branches: 2 })).subarray(65);
  const out = await upgradeOts(input, { fetchImpl: async () => new Response(foreign, { status: 200 }) });
  assert.equal(isComplete(out.candidate), true, 'it splices — the refusal happens downstream, not here');
});

test('an unreachable or refusing calendar leaves the proof pending, never falsely complete', async () => {
  const input = parseOts(serializeOts(synthetic()));
  for (const impl of [
    async () => { throw new Error('offline'); },
    async () => new Response('nope', { status: 404 }),
    async () => new Response(Buffer.alloc(20_000), { status: 200 }),   // over the size cap
    async () => new Response(Buffer.from('garbage'), { status: 200 }),
  ]) {
    const out = await upgradeOts(input, { fetchImpl: impl });
    assert.equal(isComplete(out.candidate), false);
    assert.equal(out.added, 0);
  }
});
