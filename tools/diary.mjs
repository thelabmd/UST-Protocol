// SPDX-License-Identifier: Apache-2.0
// UST diary — seal ONE entry and append it to diary.md as a prev-chained, key-form LIGHT stream.
//
// This is the machinery behind the diary described in diary.md: an agent's memory kept as a verifiable UST stream.
// Each entry is a key-form `observation` (identity = the diary key, not a domain), signed, with `prev` = the previous
// entry's content_hash — one stream, in order, no gaps. A published entry is NEVER edited; a correction is the next entry.
//
// Usage:  node tools/diary.mjs <entry-body.md>
//   entry-body.md = the human entry (a "## title" line + a few sentences of prose). Its exact text is what gets sealed,
//   so verifying the entry proves the prose is unaltered.
//
// Key: read from .env (UST_DIARY_SEED, gitignored — never committed, never printed). The public half travels in the seal.
// Note: entries are BUILT with ust-protocol (ust-lite's builder carries no provenance, so it cannot set `prev`), but the
// result is a plain key-form LIGHT observation that verifies VALID:LIGHT under BOTH ust-lite and the reference verifier.
import * as P from '../packages/ust-protocol/index.mjs';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync, appendFileSync, existsSync } from 'node:fs';

const DIARY = new URL('../diary.md', import.meta.url).pathname;
const ENV = new URL('../.env', import.meta.url).pathname;

// --- signing key from .env ---
const env = existsSync(ENV) ? readFileSync(ENV, 'utf8') : '';
const m = env.match(/^UST_DIARY_SEED=(\S+)/m);
if (!m) { console.error('✗ UST_DIARY_SEED not found in .env — generate the diary key first'); process.exit(1); }
const seed = Buffer.from(m[1], 'base64url');
const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).slice(-32).toString('base64url');
const kid = P.keyId(pub);

// --- prev = content_hash of the last sealed transcript already in diary.md (none ⇒ genesis) ---
const md = existsSync(DIARY) ? readFileSync(DIARY, 'utf8') : '';
const blocks = [...md.matchAll(/```json\n([\s\S]*?)\n```/g)].map((x) => x[1]);
let prev;
if (blocks.length) { try { prev = P.contentHash(JSON.parse(blocks[blocks.length - 1])); } catch { console.error('✗ could not parse the last entry to chain from'); process.exit(1); } }

// --- the new entry ---
const bodyPath = process.argv[2];
if (!bodyPath || !existsSync(bodyPath)) { console.error('✗ usage: node tools/diary.mjs <entry-body.md>'); process.exit(1); }
const body = readFileSync(bodyPath, 'utf8').trim();
if (!body) { console.error('✗ empty entry'); process.exit(1); }
if (body.length > 560) { console.error(`✗ entry is ${body.length} characters — the cap is 560 (two standard tweets). Cut it, don't split it.`); process.exit(1); }

const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
const ust_id = `ust:${now.slice(0, 4)}${now.slice(5, 7)}${now.slice(8, 10)}.${now.slice(11, 13)}`;
const time = { generated_at: now, valid_from: now, valid_to: now };
const state = P.buildState({ domain_shard: kid, ust_id, key_id: kid, class: 'observation' }, time,
  { entry: { kind: 'captured', value: { text: body } } }, prev ? { prev } : undefined);
const doc = P.seal(state, priv, pub);

const v = P.verify(doc, { context: 'data' });
if (v.result !== 'VALID:LIGHT') { console.error('✗ entry did not seal VALID:LIGHT:', v.result || v.error); process.exit(1); }
const ch = P.contentHash(doc);

const rows = `\n---\n\n${body}\n\n<details>\n<summary>🔒 sealed · <code>${ust_id}</code> · <code>${ch}</code> · ${prev ? 'prev <code>' + prev + '</code>' : 'genesis (no prev)'}</summary>\n\n\`\`\`json\n${JSON.stringify(doc)}\n\`\`\`\n\n</details>\n`;
appendFileSync(DIARY, rows);
console.log('✓ diary entry sealed + appended');
console.log('  ust_id      :', ust_id);
console.log('  content_hash:', ch);
console.log('  prev        :', prev || '(genesis)');
console.log('  verify      : VALID:LIGHT (key-form; verifies under ust-lite + the reference)');
