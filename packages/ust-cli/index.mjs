#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// `ust` — the reference CLI. One command hides each ceremony: verify, canon (DX diagnostic), genesis (#37).
// The Go binary (#34) reproduces this surface so `ust` is one static, language-agnostic entrypoint.
import { createInterface } from 'node:readline/promises';
import { readFileSync, writeFileSync } from 'node:fs';
import { createCipheriv, createDecipheriv, scryptSync, randomBytes } from 'node:crypto';
import * as P from 'ust-protocol';
import * as W from 'ust-web-signer';

const arg = (name, def) => { const i = process.argv.indexOf('--' + name); return i > -1 ? (process.argv[i + 1] ?? true) : def; };
const has = (name) => process.argv.includes('--' + name);
const die = (msg) => { console.error('✗ ' + msg); process.exit(1); };
const HEADER = 'UST/1.0; ref=pkg:npm/ust-protocol; web=https://thelabmd.github.io/UST-Protocol/; call=verify(doc,{context:"data"}); hash=domain-separated; trust=resolve-by-name; proves=bytes+key+time';
const blobOf = (doc) => HEADER + '\n———UST(base64)———\n' + Buffer.from(JSON.stringify(doc), 'utf8').toString('base64');
const decodeInput = (raw) => {
  let s = raw.trim(); const m = '———UST(base64)———';
  if (s.includes(m)) s = s.slice(s.lastIndexOf(m) + m.length).trim();
  return s.startsWith('{') ? JSON.parse(s) : JSON.parse(Buffer.from(s.replace(/\s+/g, ''), 'base64').toString('utf8'));
};
const nowFrame = () => W.nowFrame();

// ─── ust verify <file|-> ─────────────────────────────────────────────────────────────────────────────
async function cmdVerify() {
  const src = process.argv[3];
  if (!src) die('usage: ust verify <file | - for stdin> [--context data|key]');
  const raw = src === '-' ? readFileSync(0, 'utf8') : readFileSync(src, 'utf8');
  let doc; try { doc = decodeInput(raw); } catch (e) { die('not a UST blob/base64/json: ' + e.message); }
  const r = P.verify(doc, { context: arg('context', 'data') });
  console.log(r.result + (r.error ? '  (' + r.error + (r.detail ? ' — ' + r.detail : '') + ')' : ''));
  if (P.isValid(r)) {
    console.log('  identity : ' + r.identity.strength + ' (mode ' + r.identity.mode + ')  ' + (r.publisher ? 'publisher ' + r.publisher : 'publisher_claimed ' + r.publisher_claimed));
    console.log('  time     : ' + r.time.strength + '/' + r.time.status + '   completeness: ' + r.completeness);
    console.log('  ust_id   : ' + r.ust_id + '   class ' + r.class + '   content_hash ' + r.content_hash);
  }
  process.exit(P.isValid(r) ? 0 : 1);
}

// ─── ust canon <file|-> — the DX diagnostic (#41): print the canonical string + hash so any-language devs diff ─
async function cmdCanon() {
  const src = process.argv[3];
  if (!src) die('usage: ust canon <file | - for stdin>   # prints canonical bytes + hash to diff cross-language');
  const raw = src === '-' ? readFileSync(0, 'utf8') : readFileSync(src, 'utf8');
  let v; try { v = JSON.parse(raw); } catch (e) { die('not JSON: ' + e.message); }
  let canonical; try { canonical = P.canon(v); } catch (e) { die('E-CANON: ' + (e.detail || e.message) + '  (values must be NFC strings; no numbers/bools/nulls — §5)'); }
  console.log(canonical);
  console.error('# sha256: ' + P.H('ust:state', canonical).slice(7));
}

// ─── ust genesis --domain <d> [--profile] [--dns] — the ceremony (#37) ────────────────────────────────
const encryptKey = (pkcs8, pass) => {
  const salt = randomBytes(16), iv = randomBytes(12), key = scryptSync(pass, salt, 32);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(pkcs8), c.final()]);
  return Buffer.concat([salt, iv, c.getAuthTag(), ct]).toString('base64');
};

async function cmdGenesis() {
  const domain = arg('domain'); if (!domain || domain === true) die('usage: ust genesis --domain <name> [--profile bronze|silver|gold] [--dns manual|cf-api] [--max-partitions N] [--out .]');
  const profile = arg('profile', 'silver');
  const dns = arg('dns', 'manual');
  const outDir = arg('out', '.');
  const maxP = arg('max-partitions', profile === 'gold' ? 256 : profile === 'silver' ? 64 : null);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => rl.question(q);
  console.log(`\n  ust genesis — ceremony for ${domain} (profile: ${profile})\n`);

  // 1. root key
  console.log('  1/5  generating the ROOT key…' + (profile === 'gold' ? '  [gold: use hardware/air-gapped in production]' : ''));
  const root = await W.generateSigner({ extractable: true });
  const pkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', root.privateKey));

  // 2. genesis + first key-log (adds an operational key)
  const { ust_id, time } = nowFrame();
  const genValue = { pub: root.pub, role: 'name-binding-root', ...(maxP ? { max_partitions: String(maxP) } : {}) };
  const genesis = await W.seal(P.buildState({ domain_shard: domain, ust_id, key_id: root.key_id, class: 'genesis' }, time, { genesis: { kind: 'captured', value: genValue } }), root);
  const genHash = P.contentHash(genesis);
  const op = await W.generateSigner();
  const keylog0 = await W.seal(P.buildKeyLogEntry({ domain_shard: domain, ust_id, key_id: root.key_id }, time, { op: 'add', pub: op.pub, new_key_id: op.key_id }, genHash), root);
  console.log('  2/5  genesis built (self-signed) + key-log[0] adds an operational key');
  console.log('       genesis content_hash: ' + genHash);

  // backup the root key (gold forces a passphrase)
  let pass = '';
  if (profile === 'gold') { while (pass.length < 8) pass = await ask('       set a passphrase for the root-key backup (≥8 chars, split & cold-store): '); }
  const backup = pass ? encryptKey(pkcs8, pass) : pkcs8.toString('base64');
  writeFileSync(`${outDir}/genesis-key${pass ? '.enc' : ''}.b64`, backup);
  writeFileSync(`${outDir}/ust-genesis`, JSON.stringify(genesis));
  writeFileSync(`${outDir}/ust-keylog-0`, JSON.stringify(keylog0));
  console.log(`       wrote ${outDir}/ust-genesis + ust-keylog-0 + genesis-key${pass ? '.enc' : ''}.b64  (COLD-STORE the key)`);

  // 3. DNS (profile A) — manual or CF one-click
  const txt = `ust-genesis=${genHash}`;
  if (dns === 'cf-api') {
    const tok = process.env.CF_TOKEN || process.env.CLOUDFLARE_API_TOKEN;
    if (!tok) die('--dns cf-api needs CF_TOKEN (a ZONE-scoped DNS:edit token — never account-wide)');
    console.log('  3/5  writing _ust.' + domain + ' TXT via Cloudflare API…');
    const z = await fetch(`https://api.cloudflare.com/client/v4/zones?name=${domain}`, { headers: { Authorization: 'Bearer ' + tok } }).then((r) => r.json());
    const zone = z.result?.[0]; if (!zone) die('CF zone not found / token cannot see ' + domain);
    const w = await fetch(`https://api.cloudflare.com/client/v4/zones/${zone.id}/dns_records`, { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'content-type': 'application/json' }, body: JSON.stringify({ type: 'TXT', name: '_ust.' + domain, content: txt, ttl: 300 }) }).then((r) => r.json());
    if (!w.success) die('CF write failed: ' + (w.errors?.[0]?.message || '?'));
    console.log('       ✓ _ust.' + domain + ' TXT written (one-click, Vercel-style)');
  } else {
    console.log('  3/5  DNS (profile A, DNSSEC): add this TXT record, or skip for profile B (TLS-witness):');
    console.log('       _ust.' + domain + '  TXT  "' + txt + '"');
  }

  // 4. publish well-known + fail-closed byte-match
  console.log('  4/5  publish this file at  https://' + domain + '/.well-known/ust-genesis');
  console.log('       (the exact bytes of ' + outDir + '/ust-genesis)');
  await ask('       press Enter once it is live… ');
  try {
    const live = await fetch(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(10000) }).then((r) => r.text());
    const liveDoc = decodeInput(live);
    if (P.contentHash(liveDoc) !== genHash) die('published bytes do NOT match the genesis (content_hash differs) — republish exactly ' + outDir + '/ust-genesis');
    console.log('       ✓ well-known matches byte-for-byte (fail-closed check passed)');
  } catch (e) { die('could not verify the published well-known: ' + e.message + '  (nothing signed as authoritative — retry)'); }

  // 5. witnesses + anchor
  const witnesses = (arg('witness', '') || '').split(',').filter(Boolean);
  console.log('  5/5  witnesses: ' + (witnesses.length ? witnesses.join(', ') : (profile === 'bronze' ? 'self (bronze)' : 'none supplied — add --witness url,url for silver/gold')));
  console.log('       anchor: queue ' + genHash + ' into your anchor chain → Bitcoin/OTS (operator job)');

  console.log('\n  ✓ GENESIS DONE');
  console.log('    name         : ' + domain);
  console.log('    genesis      : ' + genHash);
  console.log('    operational  : ' + op.key_id + '  (daily key; genesis stays cold)');
  console.log('    max_partitions: ' + (maxP ?? '(default floor 64)'));
  console.log('    backup       : ' + outDir + '/genesis-key' + (pass ? '.enc' : '') + '.b64  → SPLIT + COLD STORE (needed ~yearly to rotate/revoke)\n');
  rl.close();
}

const cmd = process.argv[2];
const run = { verify: cmdVerify, canon: cmdCanon, genesis: cmdGenesis }[cmd];
if (!run) { console.error('ust — verify machine-readable state\n\n  ust verify <file|->        verify a transcript (exit 0 = VALID, 1 = not)\n  ust canon  <file|->        print canonical bytes + hash (cross-language diff)\n  ust genesis --domain <d>   run the HIGH genesis ceremony\n'); process.exit(cmd ? 1 : 0); }
run().catch((e) => die(e.message || String(e)));
