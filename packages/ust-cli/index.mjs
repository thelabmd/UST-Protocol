#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// `ust` — the reference CLI. One command hides each ceremony: verify, canon (DX diagnostic), genesis (#37).
// The Go binary (#34) reproduces this surface so `ust` is one static, language-agnostic entrypoint.
//
// The ceremony CORE is exported as pure functions (buildCeremony / checkPublished / cfUpsert / stageSummary /
// encryptKey) so a notary tool is TESTABLE end-to-end without a live network — the 9th-audit regression suite
// (regression.mjs) drives them directly. cmdGenesis is only the readline/network orchestrator around them.
import { createInterface } from 'node:readline/promises';
import { readFileSync, writeFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createCipheriv, scryptSync, randomBytes } from 'node:crypto';
import * as P from 'ust-protocol';
import * as W from '@ust-protocol/web-signer';

const arg = (name, def) => { const i = process.argv.indexOf('--' + name); return i > -1 ? (process.argv[i + 1] ?? true) : def; };
const die = (msg) => { console.error('✗ ' + msg); process.exit(1); };
const HEADER = 'UST/1.0; ref=pkg:npm/ust-protocol; web=https://thelabmd.github.io/UST-Protocol/; call=verify(doc,{context:"data"}); hash=domain-separated; trust=resolve-by-name; proves=bytes+key+time';
// ─── THE RAW BOUNDARY (rc.17, external line-review P0-1): every untrusted byte source — file, stdin,
// network, base64 blob — passes through the SAME raw path as the normative verifier. The old shape
// (decodeInput → JSON.parse → P.verify) silently ERASED duplicate JSON members before verification: a
// document the reference raw verifier rejects (E-CANON, duplicate member) verified VALID here. Parse
// happens ONLY after the raw checks.
export const rawTextOf = (raw) => {
  let s = raw.trim(); const m = '———UST(base64)———';
  if (s.includes(m)) s = s.slice(s.lastIndexOf(m) + m.length).trim();
  return s.startsWith('{') || s.startsWith('[') ? s : Buffer.from(s.replace(/\s+/g, ''), 'base64').toString('utf8');
};
// Minimal duplicate-member scanner for the ARRAY shape (a served key log), where verifyJson (single
// document) does not apply directly. The regression suite CROSS-CHECKS it against P.verifyJson on single
// documents so it can never drift silently.
// TODO(protocol): export the scanner from ust-protocol at the next spec rc and delete this copy.
export function scanDupes(text) {
  const stack = []; let i = 0, inStr = false, esc = false, key = null, expectKey = false, buf = '';
  while (i < text.length) {
    const c = text[i];
    if (inStr) {
      if (esc) { esc = false; buf += c; }
      else if (c === '\\') { esc = true; buf += c; }
      else if (c === '"') { inStr = false; if (expectKey && stack.length) key = buf; }
      else buf += c;
      i++; continue;
    }
    if (c === '"') { inStr = true; buf = ''; i++; continue; }
    if (c === '{') { stack.push(new Set()); expectKey = true; i++; continue; }
    if (c === '}') { stack.pop(); expectKey = false; i++; continue; }
    if (c === ':' && key !== null && stack.length) {
      let name; try { name = JSON.parse('"' + key + '"'); } catch { name = key; }
      const top = stack[stack.length - 1];
      if (top.has(name)) return 'duplicate member name: ' + name;
      top.add(name); key = null; expectKey = false; i++; continue;
    }
    if (c === ',') { expectKey = stack.length > 0; key = null; i++; continue; }
    if (c === '[' || c === ']') { expectKey = false; key = null; i++; continue; }
    i++;
  }
  return null;
}
// Verify a SINGLE untrusted document through the normative raw path (admission + duplicate scan + parse
// + verify). Returns { verdict, doc, text } — the caller uses doc ONLY on a valid verdict.
export function verifyRaw(raw, opts = {}) {
  // Buffer path: byte-length admission happens INSIDE verifyJson BEFORE any utf8 decode — the file is
  // never materialized as a string when the transport budget refuses it (F.9 transport refusal).
  if (Buffer.isBuffer(raw)) {
    let i = 0; while (i < raw.length && (raw[i] === 0x20 || raw[i] === 0x09 || raw[i] === 0x0a || raw[i] === 0x0d)) i++;
    const first = raw[i];
    if (first === 0x7b || first === 0x5b) {   // '{' or '['
      const verdict = P.verifyJson(raw, opts);
      if (verdict.result === 'INDETERMINATE' && verdict.reason === 'resource_limit') return { verdict, doc: null, text: null };
      const text = raw.toString('utf8');
      let doc = null; try { doc = JSON.parse(text); } catch { doc = null; }
      return { verdict, doc, text };
    }
    // base64/blob wrapper: bound the ENCODED length before decoding (decoded ≤ encoded)
    const budget = Number(opts.maxInputBytes ?? 67108864);
    if (raw.length > budget) return { verdict: { result: 'INDETERMINATE', reason: 'resource_limit', detail: `raw input ${raw.length} B > input budget ${budget} B` }, doc: null, text: null };
    raw = raw.toString('utf8');
  }
  const text = rawTextOf(raw);
  const verdict = P.verifyJson(text, opts);
  let doc = null; try { doc = JSON.parse(text); } catch { doc = null; }
  return { verdict, doc, text };
}
// Parse an untrusted ARRAY (served key log) fail-closed: duplicate scan on the RAW text, then parse,
// then each entry verifies in the key context. Returns { entries } or { err }.
export function parseKeylogRaw(raw) {
  const text = rawTextOf(raw);
  const dup = scanDupes(text);
  if (dup) return { err: 'E-CANON: ' + dup };
  let arr; try { arr = JSON.parse(text); } catch { return { err: 'not valid JSON' }; }
  if (!Array.isArray(arr)) return { err: 'a key log must be the JSON ARRAY shape' };
  for (const [i, e] of arr.entries()) {
    const v = P.verify(e, { context: 'key' });
    if (!P.isValid(v)) return { err: `key-log entry ${i} does not VERIFY (${v.error ?? v.result})` };
  }
  return { entries: arr };
}
// Convenience parse (blob/base64 → object) for bytes this tool built ITSELF or already admitted through
// verifyRaw/parseKeylogRaw. NEVER the entry point for untrusted verification input.
export const decodeInput = (raw) => JSON.parse(rawTextOf(raw));
const nowFrame = () => W.nowFrame();
// The verify context follows the record's own class: a genesis/key-log frame verifies as 'key', everything
// else as 'data'. This is why `ust verify ust-genesis` just works — no one should need to know the context.
export const contextFor = (doc) => (doc?.state?.id?.class === 'genesis' || doc?.state?.id?.class === 'key') ? 'key' : 'data';

// ─── ceremony CORE (pure, exported — a notary tool must be verifiable by tests, not just by eye) ─────────

// Hidden passphrase input (line-review P1: readline echoed the root passphrase to the terminal). Raw-mode
// character loop with '*' echo in a tty; falls back to the visible ask (with a loud warning) elsewhere.
export async function askHidden(q, fallbackAsk) {
  if (!process.stdin.isTTY) { console.log('  ⚠️  no tty — the passphrase WILL echo'); return fallbackAsk(q); }
  process.stdout.write(q);
  return await new Promise((resolve) => {
    const chars = [];
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true); stdin.resume();
    const onData = (b) => {
      const c = b.toString('utf8');
      if (c === '\r' || c === '\n') { stdin.setRawMode(wasRaw); stdin.removeListener('data', onData); process.stdout.write('\n'); resolve(chars.join('')); }
      else if (c === '\u0003') { stdin.setRawMode(wasRaw); process.stdout.write('\n'); process.exit(130); }
      else if (c === '\u007f' || c === '\b') { if (chars.length) { chars.pop(); process.stdout.write('\b \b'); } }
      else { chars.push(c); process.stdout.write('*'); }
    };
    stdin.on('data', onData);
  });
}

// gold IS the hardware tier — one refusal text, used by the core AND the interview (single source).
export const GOLD_REFUSAL = 'gold is a HARDWARE ceremony (pkcs11 / air-gapped signer). This CLI cannot drive one yet and will not pretend — run --profile silver (software root, encrypted backup), then re-root to hardware via a §12.1 supersession when ready.';

export const encryptKey = (pkcs8, pass) => {
  const salt = randomBytes(16), iv = randomBytes(12), key = scryptSync(pass, salt, 32);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(pkcs8), c.final()]);
  return Buffer.concat([salt, iv, c.getAuthTag(), ct]).toString('base64');
};

// Build genesis + key-log[0] (adds an operational key) and SELF-CHECK both (fail-closed, 9th audit #6):
// a ceremony tool must never emit an output it hasn't verified. Throws before returning if either fails.
// `warnings` carries the gold ASSURANCE LIMIT so the orchestrator (and the test) can assert it (9th audit #5).
export async function buildCeremony({ domain, profile = 'silver', maxP, maxBytes = null, signerRef }) {
  const warnings = [];
  // Each tier is about ITS OWN thing (owner 2026-07-12). gold IS the hardware ceremony — and this
  // reference CLI cannot drive a hardware signer yet, so it REFUSES instead of pretending: the old
  // behavior (software key + a warning, --signer merely silencing it) sold software as gold. Silver
  // is the honest software-root ceremony; a silver root upgrades to hardware later via §12.1
  // supersession — refusal costs nothing permanent.
  if (profile === 'gold') {
    throw new Error(GOLD_REFUSAL + (signerRef ? `  (--signer ${signerRef} was given, but no hardware driver exists here)` : ''));
  }
  const root = await W.generateSigner({ extractable: true });
  const pkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', root.privateKey));
  const { ust_id, time } = nowFrame();
  const genValue = { pub: root.pub, role: 'name-binding-root', ...(maxP ? { max_partitions: String(maxP) } : {}), ...(maxBytes ? { max_transcript_bytes: String(maxBytes) } : {}) };
  const genesis = await W.seal(P.buildState({ domain_shard: domain, ust_id, key_id: root.key_id, class: 'genesis' }, time, { genesis: { kind: 'captured', value: genValue } }), root);
  const genHash = P.contentHash(genesis);
  // operational key: extractable so its PKCS#8 can be exported for the daily signer
  // (the WARM key the producer signs with daily — under whatever secret name the
  // OPERATOR chooses; the protocol does not standardize env names. The root stays
  // cold). Without exporting it the ceremony would strand the signer.
  const op = await W.generateSigner({ extractable: true });
  const opPkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', op.privateKey));
  const keylog0 = await W.seal(P.buildKeyLogEntry({ domain_shard: domain, ust_id, key_id: root.key_id }, time, { op: 'add', pub: op.pub, new_key_id: op.key_id }, genHash), root);
  if (!P.isValid(P.verify(genesis))) throw new Error('self-check FAILED: genesis does not verify');
  if (!P.isValid(P.verify(keylog0, { context: 'key' }))) throw new Error('self-check FAILED: key-log[0] does not verify');
  return { genesis, keylog0, genHash, op, opPkcs8, pkcs8, warnings };
}

// Fail-closed check of the published well-known: it must VERIFY and its content_hash must MATCH the genesis
// we built (a semantic UST match, not a transport byte-compare — 9th audit #1). Throws on any mismatch.
export function checkPublished(liveText, genHash) {
  const { verdict, doc } = verifyRaw(liveText);   // the normative raw path — duplicates/admission included
  if (!P.isValid(verdict)) throw new Error('published document does not VERIFY' + (verdict.error ? ` (${verdict.error}${verdict.detail ? ' — ' + verdict.detail : ''})` : ''));
  if (P.contentHash(doc) !== genHash) throw new Error('published document is not this genesis (content_hash differs) — republish exactly the ust-genesis file');
  return doc;
}

// Chain sanity for a key log against ITS genesis (fail-closed before any deploy): every entry verifies
// in the key context, entry 0 chains to the genesis content_hash, each next entry chains to the previous.
// (Full revocation/authority semantics live in P.resolveAuthority — this is the publishing gate.)
export function validateKeylogChain(genesisDoc, entries) {
  let prev = P.contentHash(genesisDoc);
  for (const [i, e] of entries.entries()) {
    const v = P.verify(e, { context: 'key' });
    if (!P.isValid(v)) return `key-log entry ${i} does not VERIFY (${v.error ?? v.result})`;
    if (e.state?.provenance?.prev !== prev) return `key-log entry ${i} does not chain (prev ≠ ${i === 0 ? 'genesis' : 'entry ' + (i - 1)} content_hash)`;
    if (e.state?.id?.domain_shard !== genesisDoc.state?.id?.domain_shard) return `key-log entry ${i} belongs to a different domain_shard`;
    prev = P.contentHash(e);
  }
  return null;
}

// Independent DoH readback of the _ust TXT — shared by the cf-api path AND the by-hand path, so BOTH
// roads get the same confirmation discipline (the record is confirmed by a resolver, never by the API
// that wrote it). Returns seen/not — the CALLER decides whether absence is fatal (cf-api) or a warning
// with a re-attest pointer (by-hand: registrar TTLs can be long, the ceremony must not strand the user).
export async function dohConfirmTxt({ domain, genHash, fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), attempts = 6, delayMs = 3000, onAttempt = null }) {
  for (let i = 0; i < attempts; i++) {
    const doh = await fetchImpl(`https://cloudflare-dns.com/dns-query?name=_ust.${domain}&type=TXT`, { headers: { accept: 'application/dns-json' } }).then((r) => r.json()).catch(() => ({}));
    if ((doh.Answer || []).some((a) => (a.data || '').replace(/"/g, '').includes(genHash))) return true;
    onAttempt?.(i + 1, attempts);
    if (i < attempts - 1) await sleep(delayMs);
  }
  return false;
}

// Cloudflare one-click: UPSERT the _ust TXT (find → PUT if present, else POST) then CONFIRM it via a
// DNS-over-HTTPS readback (idempotent + fail-closed, 9th audit #7). fetchImpl/sleep are injected so the
// regression suite exercises the update-path and the readback-failure-path with no live network.
export async function cfUpsert({ domain, txt, genHash, token, fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), onAttempt = null }) {
  if (!token) throw new Error('cf-api needs a ZONE-scoped CF_TOKEN (DNS:edit for this zone — never account-wide)');
  const cf = (path, init) => fetchImpl('https://api.cloudflare.com/client/v4' + path, { ...init, headers: { Authorization: 'Bearer ' + token, 'content-type': 'application/json', ...(init?.headers) } }).then((r) => r.json());
  const zone = (await cf(`/zones?name=${domain}`)).result?.[0]; if (!zone) throw new Error('CF zone not found / token cannot see ' + domain);
  const rec = `_ust.${domain}`;
  const existing = (await cf(`/zones/${zone.id}/dns_records?type=TXT&name=${rec}`)).result?.[0];   // idempotent
  const body = JSON.stringify({ type: 'TXT', name: rec, content: txt, ttl: 300 });
  const w = existing
    ? await cf(`/zones/${zone.id}/dns_records/${existing.id}`, { method: 'PUT', body })
    : await cf(`/zones/${zone.id}/dns_records`, { method: 'POST', body });
  if (!w.success) throw new Error('CF write failed: ' + (w.errors?.[0]?.message || '?'));
  // UPDATE patience (live lesson, 2nd real ceremony): on an UPDATE the public resolver keeps serving the
  // OLD value until its TTL (300 s) expires — 18 s of readback fails a perfectly good write. Wait through
  // a full TTL window, narrated; a CREATE confirms on the first tries as before.
  const seen = await dohConfirmTxt({ domain, genHash, fetchImpl, sleep, attempts: existing ? 24 : 6, delayMs: existing ? 15000 : 3000, onAttempt });
  if (!seen) throw new Error('CF accepted the record, but the public resolver still serves the OLD value (resolver TTL cache — an updated record can take ~5 min to converge). Wait a few minutes and RE-RUN the ceremony: it is idempotent and rewrites the TXT and the worker consistently.');
  return { action: existing ? 'updated' : 'created' };
}

// ─── the BY-HAND road (owner 2026-07-12: CF is a CHOICE, not the base) — exact, actionable guidance ────
// A hands-on publisher gets told precisely WHAT to do on THEIR infra; the fail-closed confirmations are
// identical on both roads. Exported so the regression suite pins that the guidance stays concrete.
export function manualDnsGuide(domain, txt) {
  return [
    '  add this record at YOUR DNS provider (any registrar/panel works):',
    `    _ust.${domain}   TXT   "${txt}"   (TTL 300–3600)`,
    '  this is the tamper-evident DNS half of the discovery pair — it vouches for your hash outside HTTP',
    `  self-check anytime:  dig +short TXT _ust.${domain}`,
  ];
}
export function manualServingGuide(domain, outDir) {
  return [
    `  make  https://${domain}/.well-known/ust-genesis  return the EXACT bytes of ${outDir}/ust-genesis`,
    '  the §20.1 serving contract — PROPERTIES, not vendors; any stack conforms:',
    '    · methods: GET (+ HEAD) · content-type: application/json',
    '    · BOUNDED caching:  Cache-Control: public, max-age=300  — the URL is a pointer to the CURRENT',
    '      genesis; a key rotation must converge (cache longer ONLY if you purge on rotation)',
    '    · unknown query params must NOT change the response or its cache key (cache key = path)',
    '  examples:',
    '    · static host: upload the file to  <webroot>/.well-known/ust-genesis',
    '    · serve the key log the same way at  /.well-known/ust-keylog  (a JSON array — APPEND on rotation)',
    '    · nginx:  location = /.well-known/ust-genesis { alias /srv/ust/ust-genesis;',
    '              default_type application/json; add_header Cache-Control "public, max-age=300"; }',
  ];
}

// ─── CF one-click adapter (§20.1 CONVENIENCE path — the contract is infra-agnostic; this is ONE way) ───
// The genesis is EMBEDDED in the worker (an immutable ~1–2 KB document): no bucket, no extra credential
// scope, the worker IS the content. Query-robustness is NATIVE — the edge-cache key is the PATH, so an
// unknown ?param can never mint a new cache entry (§20.1 property, implemented at the layer that owns it).
// The genesis-log for the witness endpoint (#68): the publisher's OWN append-only record of every genesis
// for this name. Phase 1 carries the single active genesis; an anchor (Bitcoin OTS) is attached once its
// stamp is final — until then a verifier honestly reports "HIGH pending" (it cannot cross-check yet).
export function buildWitnessLog(genesisText, anchor = null) {
  const g = JSON.parse(genesisText);
  const genHash = P.contentHash(g);
  return JSON.stringify({ domain_shard: g.state.id.domain_shard, active: genHash,
    genesis_log: [{ content_hash: genHash, superseded_by: null, ...(anchor ? { anchor } : {}) }] });
}

export function buildWorkerScript(genesisText, keylogText = null, witnessText = null) {
  // STATELESS by design (live lesson, 3rd ceremony): the first template cached its response at the edge
  // for 24 h — a redeploy then kept serving the PREVIOUS genesis (Cache API survives worker versions).
  // The content is already IN the worker; a cache saved nothing (the invocation happens either way) and
  // created a whole staleness bug-class. No state ⇒ a redeploy is live instantly; max-age is BOUNDED so
  // downstream caches converge within the same window as the DNS TTL (§20.1 propagation bound).
  //
  // The KEY LOG rides next to the genesis (owner catch: a verifier needs BOTH to resolve the name — the
  // adapter must not leave step-3-of-HIGH as homework). Served as a JSON ARRAY so a rotation is an
  // APPEND + redeploy — the log only ever GROWS; it is never rewritten. The WITNESS log (#68) rides too at
  // /.well-known/ust-witness — the no-fork evidence surface.
  return `// ust identity serving worker — generated by @ust-protocol/cli (§20.1 serving contract, CF adapter)
const GENESIS = ${JSON.stringify(genesisText)};
const KEYLOG = ${keylogText === null ? 'null' : JSON.stringify(keylogText)};
const WITNESS = ${witnessText === null ? 'null' : JSON.stringify(witnessText)};
export default {
  async fetch(req) {
    const u = new URL(req.url);
    const body = u.pathname === '/.well-known/ust-genesis' ? GENESIS
               : (u.pathname === '/.well-known/ust-keylog' && KEYLOG !== null) ? KEYLOG
               : (u.pathname === '/.well-known/ust-witness' && WITNESS !== null) ? WITNESS
               : null;
    if (body === null) return new Response('not found', { status: 404 });
    if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('method not allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
    // §20.1 query-robustness holds trivially: identical bytes for ANY query — nothing varies, nothing is stored.
    // CORS open: the discovery pair is PUBLIC identity data — browser verifiers (the web ladder) must be
    // able to auto-resolve it cross-origin. GET/HEAD only; opening reads costs nothing.
    return new Response(req.method === 'HEAD' ? null : body, { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'public, max-age=300', 'access-control-allow-origin': '*' } });
  }
};
`;
}

// The COMBINED-auth split (owner 2026-07-12): the two halves of publishing need DIFFERENT credentials, so
// they are separable — worker+route can ride wrangler's OAuth (browser login, no manual token), leaving the
// API token with the SMALLEST possible scope: Zone.DNS:Edit on one zone. Least privilege by construction.

// Prefilled CF token-creation page (documented template URL): opens with DNS:Edit preselected — the user
// only picks the zone. Exported so tests pin the deep-link shape.
export const CF_DNS_TOKEN_URL = 'https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=' +
  encodeURIComponent(JSON.stringify([{ key: 'dns', type: 'edit' }])) + '&name=' + encodeURIComponent('ust-ceremony (DNS only — revoke after)');

// wrangler project for the OAuth path: two files, the route rides the config. Pure + testable.
export function buildWranglerProject({ domain, genesisText, keylogText = null, witnessText = null }) {
  return {
    'worker.mjs': buildWorkerScript(genesisText, keylogText, witnessText),
    'wrangler.toml': [
      `name = "ust-genesis-${domain.replaceAll('.', '-')}"`,
      'main = "worker.mjs"',
      'compatibility_date = "2026-01-01"',
      'workers_dev = false',
      `routes = [{ pattern = "${domain}/.well-known/ust-genesis*", zone_name = "${domain}" }${keylogText !== null ? `, { pattern = "${domain}/.well-known/ust-keylog*", zone_name = "${domain}" }` : ''}${witnessText !== null ? `, { pattern = "${domain}/.well-known/ust-witness*", zone_name = "${domain}" }` : ''}]`,
    ].join('\n') + '\n',
  };
}

// The MINIMAL wrangler OAuth consent for this deploy — 5 scopes, not wrangler's default 28. The default
// consent asks for wrangler's WHOLE toolbox (D1/Pages/Queues/Email/…) because OAuth scopes belong to the
// CLIENT, not the task; `--scopes` narrows the grant to exactly what deploying a worker+route needs.
export const WRANGLER_LOGIN_CMD = 'npx wrangler login --scopes account:read user:read workers_scripts:write workers_routes:write zone:read';

// OAuth half: deploy via `npx wrangler deploy` — wrangler owns the browser-login flow (the CF OAuth client
// is wrangler-only; a third-party CLI cannot run that flow itself, so we DELEGATE instead of imitating).
// stdio is inherited so the user SEES the login. execImpl/writeImpl injected — testable without a network.
// The ONE publish gate (both adapters): the genesis passes the normative RAW path, must BE class:genesis
// for THIS domain, and a key log (when given) must verify entry-by-entry AND chain from this genesis —
// all BEFORE any network write. Line-review P0-2/P0-3: nothing untrusted rides to a deploy unverified.
export function validatePublishInputs({ domain, genesisText, keylogText = null }) {
  const { verdict, doc } = verifyRaw(genesisText);
  if (!P.isValid(verdict)) throw new Error('refusing to publish: the genesis does not VERIFY' + (verdict.error ? ` (${verdict.error})` : ''));
  if (doc.state?.id?.class !== 'genesis') throw new Error(`refusing to publish: class:${doc.state?.id?.class ?? '?'} is not a genesis`);
  if (doc.state?.id?.domain_shard !== domain) throw new Error(`refusing to publish: genesis domain_shard ${doc.state?.id?.domain_shard ?? '?'} ≠ ${domain}`);
  let entries = null;
  if (keylogText !== null) {
    const parsed = parseKeylogRaw(keylogText);
    if (parsed.err) throw new Error('refusing to publish the key log: ' + parsed.err);
    const chainErr = validateKeylogChain(doc, parsed.entries);
    if (chainErr) throw new Error('refusing to publish the key log: ' + chainErr);
    entries = parsed.entries;
  }
  return { doc, genHash: P.contentHash(doc), entries };
}

export async function wranglerDeploy({ domain, genesisText, keylogText = null, witnessText = null, execImpl = null, writeImpl = null }) {
  const { genHash } = validatePublishInputs({ domain, genesisText, keylogText });
  const files = buildWranglerProject({ domain, genesisText, keylogText, witnessText });
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'ust-cf-'));
  const write = writeImpl ?? ((p, c) => writeFileSync(p, c));
  for (const [name, content] of Object.entries(files)) write(join(dir, name), content);
  const exec = execImpl ?? (async (cwd) => {
    const { spawnSync } = await import('node:child_process');
    const r = spawnSync('npx', ['wrangler', 'deploy'], { cwd, stdio: 'inherit' });
    return r.status ?? 1;
  });
  const code = await exec(dir);
  if (code !== 0) throw new Error('wrangler deploy failed (not logged in? run the MINIMAL-scope browser login and re-run):\n  ' + WRANGLER_LOGIN_CMD + '\n  (5 scopes — not wrangler\'s default 28; `wrangler logout` revokes the grant after the ceremony)');
  return { genHash, script: `ust-genesis-${domain.replaceAll('.', '-')}`, route: `${domain}/.well-known/ust-genesis*`, dir };
}

// DNS half (small-token): apex proxy check/flip + SSL advisory. Scope needed: Zone.DNS:Edit only — the SSL
// read degrades to a note when the token cannot see zone settings (never blocks the smaller scope).
export async function cfApexSteps({ domain, token, flipProxy = false, fetchImpl = fetch }) {
  if (!token) throw new Error('apex steps need a CF token with Zone.DNS:Edit for ' + domain + ' — create one prefilled: ' + CF_DNS_TOKEN_URL);
  const cf = (path, init) => fetchImpl('https://api.cloudflare.com/client/v4' + path, { ...init, headers: { Authorization: 'Bearer ' + token, ...(init?.headers) } }).then((r) => r.json());
  const zone = (await cf(`/zones?name=${domain}`)).result?.[0];
  if (!zone) throw new Error('CF zone not found / token cannot see ' + domain);

  const recs = (await cf(`/zones/${zone.id}/dns_records?name=${domain}`)).result || [];
  const apex = recs.filter((r) => ['A', 'AAAA', 'CNAME'].includes(r.type));
  const proxied = apex.some((r) => r.proxied);
  const warnings = [];
  let flipped = 0;
  if (!proxied && flipProxy) {
    for (const r of apex) {
      const p = await cf(`/zones/${zone.id}/dns_records/${r.id}`, { method: 'PATCH', body: JSON.stringify({ proxied: true }), headers: { 'content-type': 'application/json' } });
      if (!p.success) throw new Error(`proxy flip failed on ${r.type} record: ` + (p.errors?.[0]?.message || '?'));
      flipped++;
    }
  } else if (!proxied) {
    warnings.push(`apex ${domain} is DNS-only (grey): the route cannot fire. Re-run with --flip-proxy, or enable the proxy on the apex A/AAAA/CNAME records — NOTE this changes how the WHOLE site is served (origin behind CF; zone SSL mode must be Full/Strict).`);
  }
  // SSL advisory — Flexible + an https origin = redirect loops; never auto-mutate a zone-wide setting
  if (proxied || flipped) {
    try {
      const ssl = (await cf(`/zones/${zone.id}/settings/ssl`)).result?.value;
      if (ssl === 'flexible') warnings.push('zone SSL mode is FLEXIBLE — with an https origin this loops; set it to Full (strict).');
      else if (ssl === undefined) warnings.push('SSL mode not visible to this token (DNS-only scope) — verify the zone is Full (strict) in the dashboard.');
    } catch { warnings.push('SSL mode not visible to this token (DNS-only scope) — verify the zone is Full (strict) in the dashboard.'); }
  }
  return { zoneId: zone.id, proxied: proxied || flipped > 0, flipped, warnings };
}

// Full-token path (single credential, 3 scopes) — deploy worker + route via the API, then the apex steps.
// Idempotent (PUT script, list→PUT/POST route), fail-closed (the genesis must VERIFY before ANY network
// write; success is never claimed without a live attestation by the caller).
export async function cfPublish({ domain, genesisText, keylogText = null, witnessText = null, token, flipProxy = false, fetchImpl = fetch }) {
  if (!token) throw new Error('cf adapter needs CF_TOKEN (Workers Scripts:Edit + Workers Routes:Edit + DNS:Edit for this zone) — or split the scopes: `--auth wrangler` + a DNS-only token (' + CF_DNS_TOKEN_URL + ')');
  const { genHash } = validatePublishInputs({ domain, genesisText, keylogText });
  const cf = (path, init) => fetchImpl('https://api.cloudflare.com/client/v4' + path, { ...init, headers: { Authorization: 'Bearer ' + token, ...(init?.headers) } }).then((r) => r.json());

  const zone = (await cf(`/zones?name=${domain}`)).result?.[0];
  if (!zone) throw new Error('CF zone not found / token cannot see ' + domain);
  const accountId = zone.account?.id;
  if (!accountId) throw new Error('zone carries no account id — token needs zone read access');

  // 1. worker script (PUT = create-or-replace, idempotent; module syntax)
  const script = `ust-genesis-${domain.replaceAll('.', '-')}`;
  const form = new FormData();
  form.append('metadata', new Blob([JSON.stringify({ main_module: 'worker.mjs', compatibility_date: '2026-01-01' })], { type: 'application/json' }), 'metadata');
  form.append('worker.mjs', new Blob([buildWorkerScript(genesisText, keylogText, witnessText)], { type: 'application/javascript+module' }), 'worker.mjs');
  const up = await cf(`/accounts/${accountId}/workers/scripts/${script}`, { method: 'PUT', body: form });
  if (!up.success) throw new Error('worker upload failed: ' + (up.errors?.[0]?.message || '?'));

  // 2. route upsert (list → PUT if present, POST if absent — same idempotence as cfUpsert)
  const pattern = `${domain}/.well-known/ust-genesis*`;
  const routes = (await cf(`/zones/${zone.id}/workers/routes`)).result || [];
  const existing = routes.find((r) => r.pattern === pattern);
  const body = JSON.stringify({ pattern, script });
  const rt = existing
    ? await cf(`/zones/${zone.id}/workers/routes/${existing.id}`, { method: 'PUT', body, headers: { 'content-type': 'application/json' } })
    : await cf(`/zones/${zone.id}/workers/routes`, { method: 'POST', body, headers: { 'content-type': 'application/json' } });
  if (!rt.success) throw new Error('route upsert failed: ' + (rt.errors?.[0]?.message || '?'));
  // line-review P0-3: the wrangler road created BOTH routes, the API road only the genesis one — the
  // worker could answer the key-log path that Cloudflare never routed to it. Same upsert, second pattern.
  if (keylogText !== null) {
    const kp = `${domain}/.well-known/ust-keylog*`;
    const kExisting = routes.find((r) => r.pattern === kp);
    const kBody = JSON.stringify({ pattern: kp, script });
    const krt = kExisting
      ? await cf(`/zones/${zone.id}/workers/routes/${kExisting.id}`, { method: 'PUT', body: kBody, headers: { 'content-type': 'application/json' } })
      : await cf(`/zones/${zone.id}/workers/routes`, { method: 'POST', body: kBody, headers: { 'content-type': 'application/json' } });
    if (!krt.success) throw new Error('key-log route upsert failed: ' + (krt.errors?.[0]?.message || '?'));
  }
  if (witnessText !== null) {
    const wp = `${domain}/.well-known/ust-witness*`;
    const wExisting = routes.find((r) => r.pattern === wp);
    const wBody = JSON.stringify({ pattern: wp, script });
    const wrt = wExisting
      ? await cf(`/zones/${zone.id}/workers/routes/${wExisting.id}`, { method: 'PUT', body: wBody, headers: { 'content-type': 'application/json' } })
      : await cf(`/zones/${zone.id}/workers/routes`, { method: 'POST', body: wBody, headers: { 'content-type': 'application/json' } });
    if (!wrt.success) throw new Error('witness route upsert failed: ' + (wrt.errors?.[0]?.message || '?'));
  }

  // 3. apex steps (same helper as the split-auth path — ONE implementation of the blast-radius policy)
  const apex = await cfApexSteps({ domain, token, flipProxy, fetchImpl });
  return { genHash, script, route: pattern, routeAction: existing ? 'updated' : 'created', proxied: apex.proxied, flipped: apex.flipped, warnings: apex.warnings };
}

// §20.1 compliance attestation — the four discovery-serving probes, infrastructure-agnostic (the publisher
// may run ANY stack; this attests the PROPERTIES). Fail-closed on violations; what could not be checked is
// reported as `skip` (NOT ATTESTED), never silently passed. fetchImpl injected — testable without a network.
export async function attestDiscovery({ domain, mirrors = [], expectHash = null, fetchImpl = fetch }) {
  const checks = [];
  const url = `https://${domain}/.well-known/ust-genesis`;
  const get = (u, init) => fetchImpl(u, { ...init, signal: AbortSignal.timeout(10000) });

  // (1) well-known: fetch → the normative RAW path (duplicates/admission) → it must BE a genesis and it
  // must be THIS domain's genesis (line-review P0-2: a valid observation from a foreign identity served
  // at the well-known previously attested). content_hash pinned when --expect is given.
  let baseline = null, hash = null;
  try {
    const r = await get(url);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    baseline = await r.text();
    const { verdict, doc } = verifyRaw(baseline);
    if (!P.isValid(verdict)) throw new Error('published document does not VERIFY' + (verdict.error ? ` (${verdict.error})` : ''));
    if (doc.state?.id?.class !== 'genesis') throw new Error(`well-known serves class:${doc.state?.id?.class ?? '?'} — not a genesis`);
    if (doc.state?.id?.domain_shard !== domain) throw new Error(`genesis domain_shard is ${doc.state?.id?.domain_shard ?? '?'} — not ${domain}`);
    hash = P.contentHash(doc);
    if (expectHash && hash !== expectHash) throw new Error(`content_hash differs from --expect (${hash} ≠ ${expectHash})`);
    checks.push({ id: 'well-known verifies (§14, fail-closed)', status: 'pass', detail: hash });
  } catch (e) {
    checks.push({ id: 'well-known verifies (§14, fail-closed)', status: 'fail', detail: e.message });
    return { hash: null, checks, verdict: verdictOf(checks) }; // nothing downstream is meaningful without (1)
  }

  // (1b) key log: when served, it must be the ARRAY shape, every entry verifying and CHAINED to this
  // genesis; absent = NOT ATTESTED (the HIGH path needs it). Never silently untested again.
  try {
    const kr = await get(`https://${domain}/.well-known/ust-keylog`);
    if (!kr.ok) checks.push({ id: 'key log served (HIGH resolution input)', status: 'skip', detail: `HTTP ${kr.status} — not served; verifiers cannot resolve HIGH from the well-known alone` });
    else {
      const parsed = parseKeylogRaw(await kr.text());
      if (parsed.err) throw new Error(parsed.err);
      const chainErr = validateKeylogChain(decodeInput(baseline), parsed.entries);
      if (chainErr) throw new Error(chainErr);
      checks.push({ id: 'key log served (HIGH resolution input)', status: 'pass', detail: `${parsed.entries.length} entr${parsed.entries.length === 1 ? 'y' : 'ies'}, chained to this genesis` });
    }
  } catch (e) {
    checks.push({ id: 'key log served (HIGH resolution input)', status: 'fail', detail: e.message });
  }

  // (2) DNS pair: _ust TXT must carry THIS hash — and NO CONFLICTING binding may exist (line-review:
  // one matching record among conflicting ones previously passed; a forked/stale DNS state must surface)
  try {
    const doh = await get(`https://cloudflare-dns.com/dns-query?name=_ust.${domain}&type=TXT`, { headers: { accept: 'application/dns-json' } }).then((r) => r.json());
    const txts = (doh.Answer || []).map((a) => (a.data || '').replace(/"/g, ''));
    const ours = txts.filter((t) => t.startsWith('ust-genesis='));
    const conflicting = ours.filter((t) => t !== 'ust-genesis=' + hash);
    if (!ours.length) checks.push({ id: 'DNS record (_ust TXT) matches', status: 'skip', detail: 'no _ust TXT found — pair NOT ATTESTED (publish ust-genesis=<content_hash>)' });
    else if (conflicting.length) checks.push({ id: 'DNS record (_ust TXT) matches', status: 'fail', detail: `CONFLICTING binding${conflicting.length > 1 ? 's' : ''} present (${conflicting[0]}) — exactly one active ust-genesis binding is required` });
    else checks.push({ id: 'DNS record (_ust TXT) matches', status: 'pass', detail: '_ust.' + domain });
  } catch (e) {
    checks.push({ id: 'DNS record (_ust TXT) matches', status: 'skip', detail: 'DoH unreachable: ' + e.message });
  }

  // (3) query-robustness: a random unrecognized parameter MUST yield byte-identical content
  try {
    const rand = `q${randomBytes(6).toString('hex')}=${randomBytes(6).toString('hex')}`;
    const probed = await get(`${url}?${rand}`).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status} on ?query`))));
    if (probed === baseline) checks.push({ id: 'query-robustness (cache identity ⊥ unknown query)', status: 'pass', detail: '?' + rand.slice(0, 12) + '… → byte-identical' });
    else checks.push({ id: 'query-robustness (cache identity ⊥ unknown query)', status: 'fail', detail: 'response VARIES with an unknown query parameter — cache-key amplification is open (§20.1)' });
  } catch (e) {
    checks.push({ id: 'query-robustness (cache identity ⊥ unknown query)', status: 'fail', detail: e.message });
  }

  // (4) vendor-independence: every declared mirror must carry the SAME content_hash (bytes are content-
  // addressed — the mirror is untrusted, the hash decides). No mirror declared = NOT ATTESTED, never a pass.
  if (!mirrors.length) checks.push({ id: 'vendor-independence (≥1 independent mirror)', status: 'skip', detail: 'no --mirror declared — property NOT ATTESTED' });
  for (const m of mirrors) {
    try {
      const t = await get(m).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`))));
      const { verdict: mv, doc: d } = verifyRaw(t);
      if (!P.isValid(mv)) throw new Error('mirror document does not VERIFY' + (mv.error ? ` (${mv.error})` : ''));
      if (P.contentHash(d) !== hash) throw new Error('mirror carries a DIFFERENT genesis (content_hash differs)');
      checks.push({ id: 'mirror ' + m, status: 'pass', detail: 'content_hash matches' });
    } catch (e) {
      checks.push({ id: 'mirror ' + m, status: 'fail', detail: e.message });
    }
  }
  return { hash, checks, verdict: verdictOf(checks) };
}

// Verdict discipline (status honesty): ATTESTED only when everything ran AND passed; skips make it PARTIAL —
// a claim of §20.1 conformance is never granted on unchecked properties.
export function verdictOf(checks) {
  const fail = checks.filter((c) => c.status === 'fail').length;
  const skip = checks.filter((c) => c.status === 'skip').length;
  if (fail) return 'FAILED';
  return skip ? 'PARTIAL' : 'ATTESTED';
}

// ─── ceremony UX (owner 2026-07-12): the terminal must EXPLAIN the road, not just walk it ─────────────
// A first-time publisher sees WHERE they are, WHAT each step means in plain language, and WHAT comes
// next — the ceremony is a story, not an opaque sequence only its author understands.
// descriptions are pinned ≤70 chars — they must never wrap in an 80-col terminal
export const CEREMONY_STEPS = [
  ['🔑', 'ROOT key', 'the crown of the name — signs only genesis & rotations; stays cold'],
  ['📜', 'genesis + key-log', 'identity is born; a WARM key is added for daily signing'],
  ['🌐', 'DNS binding', '_ust TXT carries the genesis hash — provable outside HTTP'],
  ['📡', 'serving + live gate', 'well-known must serve EXACTLY these bytes — checked fail-closed'],
  ['⚓', 'witness / anchor', 'prepared for HIGH / TOP — the operator runs these later'],
];
export function ceremonyMap(current) {
  const lines = ['  ─── the road ───'];
  for (const [i, [e, t, d]] of CEREMONY_STEPS.entries()) {
    const mark = i < current ? '✅' : i === current ? '▶️' : '⬜';
    lines.push(`  ${mark} ${i + 1}/5 ${e} ${t}${i === current ? '\n        ' + d : ''}`);
  }
  return lines.join('\n');
}

// Live gate with PROPAGATION PATIENCE (rc.8, live lesson from the first real ceremony): after a proxy
// flip the public DNS answer takes minutes to converge — a single immediate fetch races it and fails a
// PERFECTLY GOOD deployment. Retry with spacing, narrate each attempt, stay fail-closed at the end.
export async function confirmLive({ domain, genHash, fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), attempts = 9, delayMs = 20000, onAttempt = null }) {
  let last;
  for (let i = 1; i <= attempts; i++) {
    try {
      const live = await fetchImpl(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(10000) }).then((r) => r.text());
      return checkPublished(live, genHash);
    } catch (e) {
      last = e;
      onAttempt?.(i, attempts, e.message);
      if (i < attempts) await sleep(delayMs);
    }
  }
  throw new Error(`could not confirm the published well-known after ${attempts} attempts (~${Math.round(attempts * delayMs / 60000)} min): ${last.message}\n  authoritative NOT granted. DNS/proxy propagation can take a few minutes — your artifacts are ALREADY written and the deployment may be fine; verify later with:  npx @ust-protocol/cli discovery ${domain} --expect ${genHash}`);
}

// The closing picture: WHAT exists now, WHO holds which key, WHERE you are on the tier ladder, and the
// exact next moves. Exported so the regression suite pins custody classes and the no-overclaim wording.
export function ceremonySummary({ domain, genHash, opKeyId, maxP, outDir, encrypted }) {
  return [
    '',
    '  ══════════════════════════════════════════════',
    `  ✅ GENESIS CEREMONY COMPLETE — ${domain}`,
    '  ══════════════════════════════════════════════',
    `  identity      ${genHash}`,
    `  operational   ${opKeyId}  (warm daily signer)`,
    `  capacity      max_partitions ${maxP ?? '(floor 64)'}`,
    '',
    '  📦 files & custody',
    `  ${outDir}/ust-genesis + ust-keylog-0    → PUBLIC — anyone can \`ust verify\` them`,
    `  ${outDir}/genesis-key${encrypted ? '.enc' : ''}.b64${encrypted ? '' : '        '}          → 🧊 COLD — the crown backup; keep the file and its passphrase APART`,
    `  ${outDir}/operational-key.b64           → 🔥 WARM — your producer's signing-key secret, then DELETE this file`,
    '',
    '  🎚  tier ladder — where you are',
    '  LIGHT  ✅ now   — each document verifies self-asserted: signed + intact under its carried key',
    '  HIGH   ⏳ next  — a verifier RESOLVES genesis→key-log (+ no-fork witness) and your NAME becomes',
    '                   authoritative:  npx @ust-protocol/cli verify <doc> --genesis ust-genesis --keylog ust-keylog-0 --no-fork-confirmed',
    '  TOP    ⏳ later — anchored TIME for each document (e.g. bitcoin-ots). Stream COMPLETENESS is a',
    '                   SEPARATE range verdict:  npx @ust-protocol/cli stream <frames…> --checkpoint <cp>',
    '',
    '  ➡️  next moves',
    "  1. operational-key.b64 → your producer's signing-key secret (an env var of YOUR naming), then DELETE the file",
    '  2. revoke the ceremony credentials (wrangler logout + the DNS token)',
    `  3. re-attest the serving contract anytime:  npx @ust-protocol/cli discovery ${domain}`,
    '  4. HIGH: run the witness exchange + serve the key log    5. TOP: queue the anchor',
    '  ══════════════════════════════════════════════',
  ];
}

// ─── vendor-independence: the MIRROR method (owner: a general CLI method — and never trust the user's
// word that the bytes are there; ATTEST by fetching). A mirror is BY DEFINITION on a second vendor, so
// the roads mirror the serving adapter: by-hand anywhere + a gh one-click (delegate to the vendor's own
// authenticated CLI, exactly like wrangler for CF).

// Fetch the CANONICAL surfaces (hash-verified) and attest every mirror URL against them — the mirror is
// untrusted by design: bytes are fetched, verified as UST, and content_hash-matched. Never a claim.
export async function attestMirror({ domain, genesisUrls = [], keylogUrls = [], fetchImpl = fetch }) {
  const get = (u) => fetchImpl(u, { signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`))));
  const canonical = await get(`https://${domain}/.well-known/ust-genesis`);
  const { verdict: cv, doc: canonDoc } = verifyRaw(canonical);
  if (!P.isValid(cv)) throw new Error('the canonical well-known does not VERIFY — fix serving before mirroring' + (cv.error ? ` (${cv.error})` : ''));
  if (canonDoc.state?.id?.class !== 'genesis' || canonDoc.state?.id?.domain_shard !== domain) throw new Error('the canonical well-known is not this domain\'s genesis — fix serving before mirroring');
  const canonHash = P.contentHash(canonDoc);
  let canonKeylogHashes = null; // entry hashes when the canonical key log is served
  try {
    const klParsed = parseKeylogRaw(await get(`https://${domain}/.well-known/ust-keylog`));
    if (!klParsed.err) canonKeylogHashes = klParsed.entries.map((e) => P.contentHash(e));
  } catch { /* canonical key log not served (yet) — keylog mirrors will be reported unverifiable */ }

  const results = [];
  for (const url of genesisUrls) {
    try {
      const { verdict: gv, doc: d } = verifyRaw(await get(url));
      if (!P.isValid(gv)) throw new Error('mirror document does not VERIFY' + (gv.error ? ` (${gv.error})` : ''));
      if (P.contentHash(d) !== canonHash) throw new Error('mirror carries a DIFFERENT genesis (content_hash differs)');
      results.push({ kind: 'genesis', url, status: 'pass', detail: 'content_hash matches the canonical' });
    } catch (e) { results.push({ kind: 'genesis', url, status: 'fail', detail: e.message }); }
  }
  for (const url of keylogUrls) {
    try {
      if (!canonKeylogHashes) { results.push({ kind: 'keylog', url, status: 'skip', detail: 'canonical /.well-known/ust-keylog is not served — nothing to match against' }); continue; }
      const parsed = parseKeylogRaw(await get(url));
      if (parsed.err) throw new Error(parsed.err);
      const hashes = parsed.entries.map((e) => P.contentHash(e));
      if (JSON.stringify(hashes) !== JSON.stringify(canonKeylogHashes)) throw new Error('mirror key log DIFFERS from the canonical (entry hashes differ)');
      results.push({ kind: 'keylog', url, status: 'pass', detail: `${parsed.entries.length} entr${parsed.entries.length === 1 ? 'y' : 'ies'}, hashes match` });
    } catch (e) { results.push({ kind: 'keylog', url, status: 'fail', detail: e.message }); }
  }
  return { canonHash, results, failed: results.some((r) => r.status === 'fail') };
}

// GitHub one-click: publish the mirror bytes into a PUBLIC repo via the user's own authenticated `gh`
// CLI (same delegation pattern as wrangler — we never hold the credential). Idempotent: create-or-update
// by sha. Returns the raw URLs a verifier fetches.
export async function ghMirrorPublish({ repo, dir = 'mirror', genesisText, keylogText = null, execImpl = null }) {
  const exec = execImpl ?? (async (args) => {
    const { spawnSync } = await import('node:child_process');
    const r = spawnSync('gh', args, { encoding: 'utf8' });
    if (r.status !== 0) throw new Error('gh failed: ' + (r.stderr || r.stdout || 'not logged in? run `gh auth login`').trim().slice(0, 200));
    return r.stdout;
  });
  const branch = (await exec(['api', `repos/${repo}`, '--jq', '.default_branch'])).trim() || 'main';
  const putFile = async (name, content) => {
    let sha = null;
    try { sha = (await exec(['api', `repos/${repo}/contents/${dir}/${name}?ref=${branch}`, '--jq', '.sha'])).trim() || null; } catch { sha = null; }
    const args = ['api', '-X', 'PUT', `repos/${repo}/contents/${dir}/${name}`,
      '-f', `message=ust mirror: ${name}`, '-f', `content=${Buffer.from(content).toString('base64')}`, '-f', `branch=${branch}`];
    if (sha) args.push('-f', `sha=${sha}`);
    await exec(args);
    return `https://raw.githubusercontent.com/${repo}/${branch}/${dir}/${name}`;
  };
  const genesisUrl = await putFile('ust-genesis', genesisText);
  const keylogUrl = keylogText !== null ? await putFile('ust-keylog', keylogText) : null;
  return { genesisUrl, keylogUrl, branch };
}

// The closing story every publishing flow must end with (owner: "я вообще не понимаю что мне дальше
// делать и где мой HIGH") — what just happened, the explicit PATH TO HIGH for the publisher's own
// documents, and the housekeeping. One source, printed by publish AND folded into the ceremony summary.
export function whatsNextSummary({ domain, genHash }) {
  return [
    '',
    '  ─── what just happened ───',
    '  ✅ your name has a LIVE, verifiable identity:',
    `     the genesis (${genHash.slice(0, 20)}…) is served at https://${domain}/.well-known/ust-genesis`,
    '     and pinned in DNS (_ust TXT). Anyone in the world can verify it.',
    '',
    '  ─── the path to HIGH for YOUR documents ───',
    '  ✅ 1. identity live — genesis + key-log minted, serving attested',
    '  ⬜ 2. your producer signs with the operational key',
    '        load operational-key.b64 as its signing-key secret, then DELETE the file',
    '  ⬜ 3. make the key log resolvable — the cf adapter serves it at /.well-known/ust-keylog;',
    '        by hand: publish ust-keylog-0 yourself (a verifier needs BOTH to resolve your name)',
    '  ⬜ 4. verifiers resolve — YOUR documents then verify HIGH:',
    `        npx @ust-protocol/cli verify <doc> --genesis ust-genesis --keylog ust-keylog-0 --no-fork-confirmed`,
    '  ⏳ later: witness exchange (backs the no-fork assertion) · anchor the stream → TOP',
    '',
    '  ─── housekeeping (do these NOW) ───',
    '  · revoke the ceremony credentials:  npx wrangler logout  + delete the DNS token in the dashboard',
    '  · genesis-key(.enc).b64 → cold storage; the passphrase lives APART from the file',
    `  · re-attest the serving contract anytime:  npx @ust-protocol/cli discovery ${domain}`,
  ];
}

// REMINT probe (line-review P1: the guard was fail-open — timeout/garbage/TLS-error all proceeded to
// mint). Three-state, fail-closed: 'absent' ONLY on a proven 404/410; a valid genesis for THIS domain =
// 'live'; EVERYTHING else (network error, non-UST bytes, foreign/wrong-class document) = 'indeterminate'
// — and an operation able to orphan an identity stops on indeterminate unless explicitly overridden.
export async function remintProbe({ domain, fetchImpl = fetch }) {
  let res;
  try { res = await fetchImpl(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(8000) }); }
  catch (e) { return { status: 'indeterminate', detail: 'well-known unreachable: ' + e.message }; }
  if (res.status === 404 || res.status === 410) return { status: 'absent', detail: `HTTP ${res.status}` };
  if (!res.ok) return { status: 'indeterminate', detail: `HTTP ${res.status} — neither a proven absence nor a readable identity` };
  let text; try { text = await res.text(); } catch (e) { return { status: 'indeterminate', detail: 'body unreadable: ' + e.message }; }
  try {
    const { verdict, doc } = verifyRaw(text);
    if (P.isValid(verdict) && doc.state?.id?.class === 'genesis' && doc.state?.id?.domain_shard === domain)
      return { status: 'live', hash: P.contentHash(doc), detail: 'a verifiable genesis for ' + domain };
    return { status: 'indeterminate', detail: 'the well-known serves bytes that are NOT this domain\'s genesis' };
  } catch { return { status: 'indeterminate', detail: 'the well-known serves non-UST bytes' }; }
}

// The witness/anchor stage is PREPARED, never executed by this CLI (9th audit #2). Exported so the
// regression suite asserts the wording can't silently regress to a false "witnesses verified / anchored".
export function stageSummary({ genHash, witnesses = [], profile }) {
  return [
    'witness/anchor STAGE PREPARED (not executed by this CLI):',
    'witnesses to contact: ' + (witnesses.length ? witnesses.join(', ') : (profile === 'bronze' ? 'self (bronze — no external witness)' : 'none supplied — add --witness url,url for silver/gold')),
    'anchor: queue ' + genHash + ' into your anchor chain → git + OTS/Bitcoin (operator job)',
  ];
}

// ─── ust verify <file|-> [--genesis <f> --keylog <f,f…> [--no-fork-confirmed]] ────────────────────────
// A lone document can only ever prove LIGHT; HIGH is a property of RESOLUTION (genesis→key-log), so the
// resolution inputs are FLAGS on the same command — the tier ladder is one tool, not tribal knowledge.
async function cmdVerify() {
  const src = process.argv[3];
  if (!src) die('usage: ust verify <file | - for stdin> [--context data|key] [--offline] [--genesis <file> --keylog <file[,file…]> [--no-fork-confirmed]]\n  by default the tool AUTO-RESOLVES the publisher identity from its /.well-known/ discovery pair');
  const raw = src === '-' ? readFileSync(0) : readFileSync(src);   // Buffer — admission precedes decode
  // pre-parse ONLY to pick the context — the VERDICT below comes from the normative raw path
  let doc; try { doc = decodeInput(raw.toString('utf8')); } catch (e) { die('not a UST blob/base64/json: ' + e.message); }

  // optional HIGH resolution: every input passes the RAW boundary; the capacity grant flows FROM
  // authority resolution (rc.12), never a raw caller-attached genesis. The verifier's OWN resource
  // envelope (ρ_v) is expressible: --max-input-bytes (transport) / --max-supported-bytes (capability).
  let opts = { context: arg('context', null) || contextFor(doc) };
  for (const [flag, key] of [['max-input-bytes', 'maxInputBytes'], ['max-supported-bytes', 'maxSupportedBytes']]) {
    const v = arg(flag, null);
    if (v === true) die(`--${flag} needs a value`);
    if (v !== null) opts[key] = Number(v);
  }
  // selective disclosure (F.7a): local nonce/value map + decryption keys widen what the verifier can check
  for (const [flag, key] of [['disclosures', 'disclosures'], ['dec-keys', 'decKeys']]) {
    const v = arg(flag, null);
    if (v === true) die(`--${flag} needs a value (a JSON file)`);
    if (v !== null) { try { opts[key] = JSON.parse(readFileSync(v, 'utf8')); } catch (e) { die(`could not read --${flag} ${v}: ` + e.message); } }
  }
  const genesisPath = arg('genesis', null);
  const noFork = !!arg('no-fork-confirmed', false);
  if (genesisPath && genesisPath !== true) {
    let genesisDoc, keylogDocs;
    try {
      const g = verifyRaw(readFileSync(genesisPath, 'utf8'));
      if (!P.isValid(g.verdict)) die('the --genesis file does not VERIFY (' + (g.verdict.error ?? g.verdict.result) + ')');
      genesisDoc = g.doc;
      const kl = arg('keylog', null);
      keylogDocs = (kl && kl !== true ? String(kl).split(",") : []).flatMap((pth) => {
        const t = readFileSync(pth, "utf8");
        const asArr = parseKeylogRaw(t);
        if (!asArr.err) return asArr.entries;
        const single = verifyRaw(t, { context: 'key' });
        if (!P.isValid(single.verdict)) die('the --keylog file ' + pth + ' does not VERIFY (' + (single.verdict.error ?? single.verdict.result) + ')');
        return [single.doc];
      });
    } catch (e) { die('could not read the resolution inputs: ' + e.message); }
    const auth = P.resolveAuthority(doc, { genesis: genesisDoc, keylog: keylogDocs, noForkConfirmed: noFork });
    if (auth.error) die('authority resolution failed: ' + auth.error + (auth.detail ? ' — ' + auth.detail : ''));
    opts = { ...opts, genesis: genesisDoc, keylog: keylogDocs, noForkConfirmed: noFork, capacity: auth.capacity };
  }

  let { verdict: r } = verifyRaw(raw, opts);
  // AUTO-RESOLUTION by default (owner: an agent/human receives a HIGH UST and by default sees LIGHT —
  // or, above the floor, nothing at all): the document carries its own name → fetch the §20.1 discovery
  // pair from it, resolve, re-verify with the grant. --offline forbids the network. Honesty holds:
  // HIGH still requires YOUR --no-fork-confirmed — auto-resolution never silently grants authority.
  let resolution = null;
  if (!genesisPath) {
    // the SINGLE resolver (ust-protocol resolveByDiscovery, rc.13) — SSRF guard + one-copy flow live there
    // opt-in Bitcoin cross-check: if @ust-protocol/ots-verify is installed, the witness genesis anchor is
    // verified against Bitcoin (→ live HIGH); if not, the anchor stays unproven (→ honest HIGH pending).
    // opt-in substrate plugins: Bitcoin (ots-verify) + Rekor (rekor-verify), combined via the protocol
    // router. Whichever are installed contribute; none installed → anchor unproven → honest HIGH-pending.
    const plugins = [];
    for (const pkg of ['@ust-protocol/ots-verify', '@ust-protocol/rekor-verify']) {
      try { const m = await import(pkg); if (m.substrateVerify) plugins.push(m.substrateVerify); } catch { /* absent */ }
    }
    const substrateVerify = plugins.length ? P.combineSubstrates(plugins) : undefined;
    const rd = await P.resolveByDiscovery(doc, { context: opts.context, offline: !!arg('offline', false), noForkConfirmed: noFork },
      { substrateVerify, fetchImpl: async (u, init) => { console.error(`  ⏳ resolving identity from ${new URL(u).origin} … (--offline to skip)`); return fetch(u, init); } });
    if (!substrateVerify && rd.resolution && String(rd.resolution.noFork || '').startsWith('HIGH pending')) console.error('  ℹ️  anchor not cross-checked — `npm i @ust-protocol/ots-verify @ust-protocol/rekor-verify` for automatic HIGH');
    if (rd.resolution) {
      r = rd.verdict;
      resolution = rd.resolution.skipped ? { error: rd.resolution.skipped }
                 : rd.resolution.error ? { error: rd.resolution.error }
                 : rd.resolution.fork ? { error: rd.resolution.detail }
                 : { publisher: rd.resolution.publisher, capacity: rd.resolution.capacity, noFork: noFork ? 'asserted by you (--no-fork-confirmed)' : rd.resolution.noFork };
    }
  }
  console.log(r.result + (r.error ? '  (' + r.error + (r.detail ? ' — ' + r.detail : '') + ')' : ''));
  if (resolution) {
    if (resolution.error) console.log('  resolve  : ✗ ' + resolution.error);
    else console.log("  resolve  : key ∈ " + resolution.publisher + "'s chain · capacity " + (resolution.capacity.maxPartitions ?? 'floor') + ' admitted · no-fork ' + resolution.noFork);
  }
  if (P.isValid(r)) {
    const tier = r.result.split(':')[1] ?? 'LIGHT';
    console.log('  identity : ' + r.identity.strength + ' (mode ' + r.identity.mode + ')  ' + (r.publisher ? 'publisher ' + r.publisher : 'publisher_claimed ' + r.publisher_claimed));
    console.log('  time     : ' + r.time.strength + '/' + r.time.status + '   completeness: ' + r.completeness);
    console.log('  ust_id   : ' + r.ust_id + '   class ' + r.class + '   content_hash ' + r.content_hash);
    if (r.provenance) console.log('  lineage  : declared' + (r.provenance.referents ? `, referents ${r.provenance.referents}` : '') + (r.provenance.depth !== undefined ? ` (walk depth ${r.provenance.depth})` : '') + ' — a declaration is not a verified derivation');
    console.log('  tier     : ' + ['LIGHT', 'HIGH', 'TOP'].map((t) => (t === tier ? `[${t}]` : ` ${t} `)).join('→'));
    if (tier === 'LIGHT' && resolution && !resolution.error && !noFork) {
      console.log('\n  ℹ️  the name RESOLVED (key belongs to its chain, capacity admitted) but stays provisional');
      console.log('     without the no-fork witness. Once you have independently confirmed no rival genesis');
      console.log('     exists, re-run with:  --no-fork-confirmed   → VALID:HIGH');
    } else if (tier === 'LIGHT' && !genesisPath && !resolution) {
      console.log('\n  ✅ this is the EXPECTED result for a lone document — it proves the file is signed and');
      console.log('     intact under the key it carries. HIGH is a property of RESOLUTION, not of the file:');
      console.log('     npx @ust-protocol/cli verify <doc> --genesis <ust-genesis> --keylog <ust-keylog-0> --no-fork-confirmed');
    } else if (tier === 'LIGHT' && genesisPath && !noFork) {
      console.log('\n  ℹ️  resolution ran but the name is not authoritative WITHOUT the no-fork witness check.');
      console.log('     Once your witness exchange confirms no rival genesis exists, add: --no-fork-confirmed');
    } else if (tier === 'HIGH') {
      console.log('\n  🏛  the NAME is authoritative: genesis→key-log resolved' + (noFork ? ' (+ no-fork asserted by YOU — that assertion is your operator duty)' : ''));
      console.log('     TOP is next: anchored TIME per document. Completeness is a SEPARATE range verdict (ust stream).');
    }
  }
  // three-valued exit contract: absence of information is NOT proven invalidity (F.5)
  process.exit(P.isValid(r) ? 0 : r.result === 'INDETERMINATE' ? 2 : 1);
}

// ─── ust canon <file|-> — the DX diagnostic (#41): print the canonical string + hash so any-language devs diff ─
async function cmdCanon() {
  const src = process.argv[3];
  if (!src) die('usage: ust canon <file | - for stdin>   # prints canonical bytes + hash to diff cross-language');
  const raw = src === '-' ? readFileSync(0, 'utf8') : readFileSync(src, 'utf8');
  const dup = scanDupes(rawTextOf(raw));
  if (dup) die('E-CANON: ' + dup + '  (duplicate members are rejected at the RAW boundary — §6)');
  let v; try { v = JSON.parse(rawTextOf(raw)); } catch (e) { die('not JSON: ' + e.message); }
  // a FULL transcript hashes over canon({ust,state}) — printing the hash of canon(whole doc) as if it
  // were a content_hash mislabels the domain (external review): split the two cases honestly.
  if (v && typeof v === 'object' && v.ust && v.state) {
    let canonical; try { canonical = P.canon({ ust: v.ust, state: v.state }); } catch (e) { die('E-CANON: ' + (e.detail || e.message)); }
    console.log(canonical);
    console.error('# canonical SIGNED CONTENT of a transcript ({ust,state})');
    console.error('# content_hash: ' + P.contentHash(v));
    return;
  }
  let canonical; try { canonical = P.canon(v); } catch (e) { die('E-CANON: ' + (e.detail || e.message) + '  (values must be NFC strings; no numbers/bools/nulls — §5)'); }
  console.log(canonical);
  console.error('# sha256 (generic canonical hash — NOT a content_hash: the input is not a {ust,state} transcript): ' + P.H('ust:state', canonical).slice(7));
}

// ─── ust discovery <domain> — §20.1 compliance attestation (any infra; properties, not mechanisms) ────
async function cmdDiscovery() {
  const domain = process.argv[3];
  if (!domain || domain.startsWith('--')) die('usage: ust discovery <domain> [--mirror url,url] [--expect sha256:…]   # attest the §20.1 serving contract');
  const mirrors = (arg('mirror', '') || '').split(',').filter(Boolean);
  const expectHash = arg('expect', null);
  const { hash, checks, verdict } = await attestDiscovery({ domain, mirrors, expectHash });
  const mark = { pass: '✅', fail: '❌', skip: '⬜' };
  for (const c of checks) console.log(`  ${mark[c.status]}  ${c.id}${c.detail ? '  (' + c.detail + ')' : ''}`);
  console.log(`\n  DISCOVERY CONFORMANCE (§20.1): ${verdict}${hash ? '   genesis ' + hash : ''}   (exit: 0=ATTESTED · 2=PARTIAL · 1=FAILED)`);
  if (verdict === 'PARTIAL') {
    // targeted hints (rc.8): name ONLY what was actually skipped — never advise republishing what already passed
    console.log('  PARTIAL = no violation found, but unchecked properties remain:');
    for (const c of checks.filter((x) => x.status === 'skip')) {
      if (c.id.startsWith('DNS record')) console.log('    → publish the _ust TXT (ust-genesis=<content_hash>) and re-run');
      else if (c.id.startsWith('vendor-independence')) console.log(`    → declare an independent mirror:  npx @ust-protocol/cli discovery ${domain} --mirror <url>`);
      else console.log('    → ' + c.id + ' — ' + c.detail);
    }
  }
  process.exit(verdict === 'FAILED' ? 1 : verdict === 'PARTIAL' ? 2 : 0);
}

// Resolve the DNS-scope token for the COMBINED flow: env first; interactively, open the PREFILLED
// creation page (DNS:Edit preselected — the user only picks the zone) and ask for a paste. Fail-closed
// in non-tty (an unattended run must be given the token, never prompted).
async function resolveDnsToken(ask) {
  const env = process.env.CF_TOKEN || process.env.CLOUDFLARE_API_TOKEN;
  if (env) return env;
  if (!ask || !process.stdin.isTTY) throw new Error('no CF token: set CF_TOKEN (Zone.DNS:Edit only) — create one prefilled: ' + CF_DNS_TOKEN_URL);
  console.log('  no CF_TOKEN — create a DNS-ONLY token (smallest scope; revoke after the ceremony):');
  console.log('  ' + CF_DNS_TOKEN_URL);
  const t = (await ask('  paste the token here: ')).trim();
  if (!t) throw new Error('no token pasted');
  return t;
}

// ─── ust publish cf --domain <d> --genesis <file> — the CF one-click serving adapter (§20.1) ──────────
async function cmdPublish() {
  const provider = process.argv[3];
  if (provider !== 'cf') die('usage: ust publish cf --domain <d> --genesis <ust-genesis file> [--auth wrangler] [--flip-proxy] [--mirror url,url]\n  (cf is the first convenience adapter — the §20.1 contract itself is infrastructure-agnostic; `ust discovery` attests ANY stack)');
  const domain = arg('domain'); if (!domain || domain === true) die('--domain is required');
  const genPath = arg('genesis'); if (!genPath || genPath === true) die('--genesis <path to the ust-genesis file> is required');
  const genesisText = readFileSync(genPath, 'utf8');
  const flipProxy = !!arg('flip-proxy', false);
  // the key log rides along by default: --keylog <file>, or ust-keylog-0 found NEXT to the genesis file.
  // A single entry file is wrapped into the served ARRAY shape (a rotation later APPENDS, never rewrites).
  let keylogText = null;
  const klPath = arg('keylog', null) || genPath.replace(/[^/\\]+$/, 'ust-keylog-0');
  try {
    const klRaw = readFileSync(klPath, 'utf8');
    const kl = decodeInput(klRaw);
    keylogText = JSON.stringify(Array.isArray(kl) ? kl : [kl]);
  } catch { if (arg('keylog', null)) die('could not read --keylog ' + klPath); }

  let r;
  if (arg('auth', null) === 'wrangler') {
    // COMBINED flow: worker+route ride wrangler's OAuth (browser login — no workers scopes on any token);
    // the API token shrinks to Zone.DNS:Edit for the apex steps.
    let w; try { w = await wranglerDeploy({ domain, genesisText, keylogText, witnessText: buildWitnessLog(genesisText) }); } catch (e) { die(e.message); }
    console.log('  ✓ worker ' + w.script + ' deployed via wrangler OAuth (genesis embedded, ' + w.genHash + ')');
    console.log('  ✓ route ' + w.route + ' (from wrangler.toml)');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    let apex; try { apex = await cfApexSteps({ domain, token: await resolveDnsToken((q) => rl.question(q)), flipProxy }); }
    catch (e) { rl.close(); die(e.message); }
    rl.close();
    r = { ...w, routeAction: 'wrangler', proxied: apex.proxied, flipped: apex.flipped, warnings: apex.warnings };
  } else {
    const token = process.env.CF_TOKEN || process.env.CLOUDFLARE_API_TOKEN;
    try { r = await cfPublish({ domain, genesisText, keylogText, witnessText: buildWitnessLog(genesisText), token, flipProxy }); } catch (e) { die(e.message); }
    console.log('  ✓ worker ' + r.script + ' deployed (genesis embedded, ' + r.genHash + ')');
    console.log('  ✓ route ' + r.route + ' ' + r.routeAction);
  }
  if (r.flipped) console.log(`  ✓ proxy enabled on ${r.flipped} apex record${r.flipped > 1 ? 's' : ''}`);
  for (const w of r.warnings) console.log('  ⚠  ' + w);
  if (!r.proxied) { console.log('\n  NOT LIVE YET — the apex is not proxied; nothing to attest.'); process.exit(1); }
  // fail-closed: deployment is only DONE when the live surface attests (§20.1 probes)
  const mirrors = (arg('mirror', '') || '').split(',').filter(Boolean);
  const a = await attestDiscovery({ domain, mirrors, expectHash: r.genHash });
  const mark = { pass: '✅', fail: '❌', skip: '⬜' };
  for (const c of a.checks) console.log(`  ${mark[c.status]}  ${c.id}${c.detail ? '  (' + c.detail + ')' : ''}`);
  console.log(`\n  DISCOVERY CONFORMANCE (§20.1): ${a.verdict}${a.verdict === 'PARTIAL' ? '  — no violation; only undeclared properties left unattested (e.g. a mirror)' : ''}`);
  // the flow must never just STOP at a verdict — close the story: what happened, the path to HIGH, housekeeping
  if (a.verdict !== 'FAILED') for (const l of whatsNextSummary({ domain, genHash: r.genHash })) console.log(l);
  process.exit(a.verdict === 'FAILED' ? 1 : a.verdict === 'PARTIAL' ? 2 : 0);
}

// ─── ust stream <frame…> — the RANGE verdict (F.4): chain, forks, checkpoint, completeness ───────────
// Completeness is NEVER a single document's property — this command is where it legitimately lives.
async function cmdStream() {
  const files = process.argv.slice(3).filter((a) => !a.startsWith('--'));
  if (!files.length) die('usage: ust stream <frame.json…> [--genesis <f>] [--checkpoint <f>]   # range verdict: chain · forks · completeness\n  exit: 0=proven · 2=provisional/none · 1=broken');
  const frames = [];
  for (const f of files) {
    const { verdict, doc } = verifyRaw(readFileSync(f));   // every frame passes the RAW boundary
    if (!P.isValid(verdict)) die(`frame ${f} does not VERIFY (${verdict.error ?? verdict.result})`);
    frames.push(doc);
  }
  const rd = (flag) => { const v = arg(flag, null); if (v === true) die(`--${flag} needs a value`); if (!v) return null;
    const { verdict, doc } = verifyRaw(readFileSync(v)); if (!P.isValid(verdict)) die(`--${flag} file does not VERIFY (${verdict.error ?? verdict.result})`); return doc; };
  const genesis = rd('genesis');
  const checkpoint = rd('checkpoint');
  const r = P.verifyStream(frames, { ...(genesis ? { genesis } : {}), ...(checkpoint ? { checkpoint } : {}) });
  if (r.error) { console.log(`  ❌ stream BROKEN: ${r.error}${r.detail ? ' — ' + r.detail : ''}`); process.exit(1); }
  console.log('  frames      ' + frames.length);
  console.log('  authority   ' + (frames[0]?.state?.id?.domain_shard ?? '?') + (genesis ? '  (origin: genesis-bound)' : '  (origin: unbound — no --genesis)'));
  console.log('  completeness ' + r.complete + (checkpoint ? '' : '   (no --checkpoint — proven is unreachable without one)'));
  console.log('\n  completeness is a RANGE verdict over THESE frames — it never upgrades any single document\'s tier');
  process.exit(r.complete === 'proven' ? 0 : 2);
}

// ─── ust mirror <domain> — vendor-independence on a SECOND vendor, attested never claimed ─────────────
async function cmdMirror() {
  const domain = process.argv[3];
  if (!domain || domain.startsWith('--')) die('usage: ust mirror <domain> [--publish gh --repo owner/repo [--dir mirror]] [--url g1,g2] [--keylog-url k1]\n  publish/attest EXACT copies of your live identity on a SECOND vendor (§20.1 vendor-independence)');
  const tty = !!process.stdin.isTTY;
  const genesisUrls = String(arg('url', '') || '').split(',').filter(Boolean);
  const keylogUrls = String(arg('keylog-url', '') || '').split(',').filter(Boolean);

  if (arg('publish', null) === 'gh') {
    const repoFlag = arg('repo'); if (!repoFlag || repoFlag === true) die('--repo owner/repo is required for --publish gh (a PUBLIC repo — the mirror must be readable by anyone)');
    const dirFlag = arg('dir', 'mirror') === true ? 'mirror' : arg('dir', 'mirror');
    console.log('  ⏳ fetching the canonical bytes from https://' + domain + '/.well-known/…');
    let g; try { g = await fetch(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.text() : Promise.reject(new Error('canonical genesis unreachable: HTTP ' + r.status)))); } catch (e) { die(e.message); }
    let k = null;
    try { const kr = await fetch(`https://${domain}/.well-known/ust-keylog`, { signal: AbortSignal.timeout(10000) }); k = kr.ok ? await kr.text() : null; } catch { k = null; }
    console.log('  ⏳ publishing via YOUR gh CLI (create-or-update, idempotent — this tool holds no credential)…');
    let pub; try { pub = await ghMirrorPublish({ repo: repoFlag, dir: dirFlag, genesisText: g, keylogText: k }); } catch (e) { die(e.message); }
    console.log('  ✅ pushed: ' + pub.genesisUrl);
    if (pub.keylogUrl) console.log('  ✅ pushed: ' + pub.keylogUrl);
    else console.log('  ⬜ the canonical key log is not served yet — redeploy serving first, then re-run mirror');
    genesisUrls.push(pub.genesisUrl);
    if (pub.keylogUrl) keylogUrls.push(pub.keylogUrl);
  } else if (!genesisUrls.length && tty) {
    console.log('  by hand on a SECOND vendor (any static host / object storage / another CDN — NOT your primary):');
    console.log('    1. download the canonical bytes:');
    console.log(`       curl -o ust-genesis  https://${domain}/.well-known/ust-genesis`);
    console.log(`       curl -o ust-keylog   https://${domain}/.well-known/ust-keylog    (if served)`);
    console.log('    2. upload them anywhere PUBLIC on that second vendor');
    console.log('    3. paste the URL(s) — I will FETCH and hash-match them (a claim is not a proof)');
    const rl2 = createInterface({ input: process.stdin, output: process.stdout });
    const gu = (await rl2.question('  genesis mirror URL: ')).trim();
    const ku = (await rl2.question('  key-log mirror URL (Enter to skip): ')).trim();
    rl2.close();
    if (gu) genesisUrls.push(gu);
    if (ku) keylogUrls.push(ku);
  }
  if (!genesisUrls.length) die('nothing to attest: give --url, use --publish gh, or answer interactively');

  console.log('\n  ⏳ attesting the mirror(s) — fetching and hash-matching against the canonical…');
  let m; try { m = await attestMirror({ domain, genesisUrls, keylogUrls }); } catch (e) { die(e.message); }
  const mark = { pass: '✅', fail: '❌', skip: '⬜' };
  for (const r of m.results) console.log(`  ${mark[r.status]}  [${r.kind}] ${r.url}  (${r.detail})`);

  // fold into the FULL §20.1 verdict — an attested mirror is what flips PARTIAL → ATTESTED
  console.log('\n  ⏳ full §20.1 attestation with the mirror declared…');
  const a = await attestDiscovery({ domain, mirrors: genesisUrls, expectHash: m.canonHash });
  for (const c of a.checks) console.log(`  ${mark[c.status]}  ${c.id}${c.detail ? '  (' + c.detail + ')' : ''}`);
  const complete = a.verdict === 'ATTESTED' && !m.failed;
  console.log(`\n  RESULT: ${complete ? '✅ COMPLETE — every §20.1 property attested, vendor-independence included' : m.failed || a.verdict === 'FAILED' ? '❌ FAILED — fix the ❌ lines above and re-run' : '⬜ PARTIAL — see the ⬜ lines above'}`);
  if (complete) {
    console.log('  keep the mirror URL(s) declared to your consumers (operator profile) and re-attest anytime:');
    console.log(`    npx @ust-protocol/cli discovery ${domain} --mirror ${genesisUrls[0]}`);
  }
  process.exit(m.failed || a.verdict === 'FAILED' ? 1 : a.verdict === 'PARTIAL' ? 2 : 0);
}

// ─── ust genesis --domain <d> [--profile] [--dns] — the ceremony (#37), orchestrating the core above ──
async function cmdGenesis() {
  const domain = arg('domain'); if (!domain || domain === true) die('usage: ust genesis --domain <name> [--profile bronze|silver|gold] [--dns manual|cf-api] [--publish cf [--auth wrangler] [--flip-proxy]] [--signer <ref>] [--witness url,url] [--max-partitions N] [--out .]\n  every option is also asked INTERACTIVELY — the flags only preselect');
  const signerRef = arg('signer', null);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => rl.question(q);
  const tty = !!process.stdin.isTTY;
  console.log(`\n  🏛  ust genesis — the HIGH ceremony for ${domain}`);
  console.log('      One run creates your name\'s cryptographic identity and makes it publicly');
  console.log('      discoverable. Everything is verified fail-closed before it is claimed.\n');
  console.log(ceremonyMap(0));

  // ── REMINT GUARD (fail-closed, rc.17): 'absent' is the ONLY state that proceeds silently. A live
  // identity requires typed REMINT; an INDETERMINATE state (network error / garbage / foreign document)
  // also STOPS — those were previously indistinguishable from absence, on an identity-orphaning op.
  {
    const probe = await remintProbe({ domain });
    if (probe.status === 'live') {
      console.log(`\n  ⚠️  an identity for ${domain} is ALREADY LIVE: ${probe.hash.slice(0, 28)}…`);
      console.log('     re-running the ceremony MINTS A NEW IDENTITY and orphans the live one.');
      console.log('     KEY ROTATION is different: a key-log APPEND under the SAME identity (root stays,');
      console.log('     old documents stay valid) — never a new ceremony.');
      if (!arg('remint', false)) {
        if (!tty) { rl.close(); die('an identity is already live — pass --remint to consciously replace it'); }
        const a = (await ask('     type REMINT to replace it, anything else aborts: ')).trim();
        if (a !== 'REMINT') { rl.close(); die('aborted — the live identity stays untouched'); }
      }
    } else if (probe.status === 'indeterminate' && !arg('remint-unchecked', false)) {
      console.log(`\n  ⚠️  REMINT STATUS INDETERMINATE: ${probe.detail}`);
      console.log('     I cannot PROVE no identity is live at ' + domain + ' — and minting over a live one orphans it.');
      if (!tty) { rl.close(); die('remint status indeterminate — pass --remint-unchecked to proceed anyway'); }
      const a = (await ask('     type UNCHECKED to proceed anyway, anything else aborts: ')).trim();
      if (a !== 'UNCHECKED') { rl.close(); die('aborted — resolve the well-known state first (or --remint-unchecked)'); }
    }
  }

  // ── the INTERVIEW (rc.10, owner catch): every choice IS a choice — flags preselect, otherwise the
  // ceremony asks, each question carrying its meaning. A dangling value-flag is an ERROR headless and
  // just re-asked in a tty. Nothing is silently dictated.
  const askOr = async (flag, question, def, validate) => {
    let v = arg(flag, null);
    if (v === true) { if (!tty) die(`--${flag} needs a value`); v = null; }
    if (v === null && tty) { const a = (await ask(question)).trim(); v = a === '' ? def : a; }
    if (v === null) v = def;
    if (validate && !validate(String(v))) die(`--${flag}: "${v}" is not a valid value`);
    return v;
  };

  console.log('\n  ⚙️  a few choices, Enter accepts the [default]:');
  console.log('\n  profile = how much ceremony rigor:');
  console.log('    bronze  quick floor (plain backup)     silver  software root + ENCRYPTED backup');
  console.log('    gold    HARDWARE root (pkcs11/air-gap) — refused honestly until this CLI can drive one');
  const profile = await askOr('profile', '  profile [silver]: ', 'silver', (v) => ['bronze', 'silver', 'gold'].includes(v));
  if (profile === 'gold') { rl.close(); die(GOLD_REFUSAL); }   // refuse NOW — not after three more questions

  console.log('\n  capacity = max partitions your documents may DECLARE (signed into the genesis,');
  console.log('  ceremony-earned; ABS ceiling 4096). More sources/fields later ⇒ pick headroom now.');
  const defP = profile === 'gold' ? 256 : profile === 'silver' ? 64 : null;
  const maxP = await askOr('max-partitions', `  max_partitions [${defP ?? 'floor 64'}]: `, defP, (v) => v === null || (Number(v) > 0 && Number(v) <= 4096));

  // NOT a question (owner: you already chose your directory by standing in it) — the files go to the
  // current dir; --out exists for scripted/special cases and is simply SHOWN, never asked.
  let outDir = arg('out', '.');
  if (outDir === true) { if (!tty) die('--out needs a value'); outDir = '.'; }

  // the road is a CHOICE, not a vendor default: by hand on YOUR infra (exact guidance) or one-click.
  let dnsMode = arg('dns', null);
  let publishMode = arg('publish', null);
  let authMode = arg('auth', null);
  if (!dnsMode && !publishMode && tty) {
    console.log('\n  How will you publish your identity? (both roads end at the same fail-closed checks)');
    console.log('    [1] by hand on MY infra — exact instructions for any DNS panel / any web stack');
    console.log('    [2] Cloudflare one-click — wrangler browser login (5 scopes) + a DNS-only token');
    console.log('        (credentials are asked ONLY when actually needed, with a prefilled link)');
    const a = (await ask('  choose 1 or 2 [1]: ')).trim();
    if (a === '2') { dnsMode = 'cf-api'; publishMode = 'cf'; authMode = authMode || 'wrangler'; }
  }
  dnsMode = dnsMode || 'manual';
  console.log(`\n  ⚙️  profile ${profile} · max_partitions ${maxP ?? '(floor 64)'}${arg('max-transcript-bytes', null) && arg('max-transcript-bytes', null) !== true ? ' · max_transcript_bytes ' + arg('max-transcript-bytes', null) : ''} · road ${publishMode === 'cf' ? 'cloudflare one-click' : 'by hand'}`);
  console.log(`      files → ${outDir === '.' ? process.cwd() : outDir}  (override with --out)`);
  // one token, asked ONCE at first need — steps 3 and 4 share it (never a double paste-prompt)
  let dnsTokenMemo = null;
  const getDnsToken = async () => (dnsTokenMemo ??= await resolveDnsToken(ask));

  // 1–2. root key + genesis + key-log[0], all self-checked (fail-closed) inside buildCeremony
  const maxBytes = arg('max-transcript-bytes', null);
  if (maxBytes === true) { rl.close(); die('--max-transcript-bytes needs a value'); }
  let built; try { built = await buildCeremony({ domain, profile, maxP, maxBytes, signerRef }); }
  catch (e) { rl.close(); die(e.message); }
  const { genesis, keylog0, genHash, op, opPkcs8, pkcs8, warnings } = built;
  for (const w of warnings) console.log('\n  ⚠️  ' + w);
  console.log('\n  ✅ 1/5 🔑 ROOT key generated — it exists only in this process right now');
  console.log('\n' + ceremonyMap(1));
  console.log('\n  ✅ 2/5 📜 genesis built (self-signed by the root) + key-log[0] adds the operational key');
  console.log('       your identity from now on = this hash:');
  console.log('       ' + genHash);

  // backup the root key (gold forces a passphrase → AES-256-GCM; the file is an encrypted blob, NOT a UST)
  let pass = '';
  if (profile !== 'bronze') {   // silver+: the software-operator ceremony encrypts the root backup
    console.log('\n  🧊 The root key is about to be written to disk ENCRYPTED. The passphrase you set now');
    console.log('     is the ONLY way to open that backup — store the file and the phrase in DIFFERENT');
    console.log('     places (split custody). You will need it roughly once a year (rotate/revoke).');
    while (pass.length < 8) pass = await askHidden('     set the passphrase (≥8 chars): ', ask);
  }
  const backup = pass ? encryptKey(pkcs8, pass) : pkcs8.toString('base64');
  // custody hardening (line-review P1): key material is 0600 and NEVER silently overwritten ('wx') —
  // a local re-run cannot clobber an existing root backup; public identity docs also refuse overwrite.
  const writeSecret = (path, data) => writeFileSync(path, data, { mode: 0o600, flag: 'wx' });
  const writePublic = (path, data) => writeFileSync(path, data, { flag: 'wx' });
  try {
    writeSecret(`${outDir}/genesis-key${pass ? '.enc' : ''}.b64`, backup);
  // operational key = the WARM daily signer. Written PLAIN base64 PKCS8 because the
  // producer loads it non-interactively from its signing-key env. It is NOT cold-store:
  // move it into the producer's secret store, then delete this file — never commit it.
    writeSecret(`${outDir}/operational-key.b64`, opPkcs8.toString('base64'));
    writePublic(`${outDir}/ust-genesis`, JSON.stringify(genesis));
    writePublic(`${outDir}/ust-keylog-0`, JSON.stringify(keylog0));
  } catch (e) {
    rl.close();
    die(e.code === 'EEXIST'
      ? `refusing to overwrite an existing ceremony file (${e.path}). Move the previous ceremony's files away (or run with --out <fresh dir>) and re-run — key material is never silently clobbered.`
      : e.message);
  }
  console.log('\n  📦 four files written to ' + outDir + ':');
  console.log('     ust-genesis + ust-keylog-0          → PUBLIC identity documents (verifiable by anyone)');
  console.log(`     genesis-key${pass ? '.enc' : ''}.b64${pass ? '' : '    '}                 → 🧊 COLD crown backup (file + passphrase apart)`);
  console.log("     operational-key.b64                 → 🔥 WARM daily signer → your producer's signing-key secret, then DELETE");
  console.log('     self-check: genesis + key-log verify ✓ (this tool never emits what it has not verified)');

  // 3. DNS (profile A) — manual paste or CF one-click (upsert + DoH readback)
  console.log('\n' + ceremonyMap(2));
  const txt = `ust-genesis=${genHash}`;
  if (dnsMode === 'cf-api') {
    console.log('\n  ▶️  3/5 🌐 the DNS half needs the DNS-only token (asked NOW because it is needed NOW):');
    let res;
    try {
      const dnsToken = await getDnsToken();   // env if set; otherwise the prefilled link + a paste (asked once)
      console.log('  ⏳ writing _ust.' + domain + ' TXT via the Cloudflare API (upsert + DoH readback)…');
      res = await cfUpsert({
        domain, txt, genHash, token: dnsToken,
        onAttempt: (i, n) => console.log(`     ⏳ readback ${i}/${n} — the resolver still serves the previous record (TTL up to 300 s), waiting…`),
      });
    } catch (e) { rl.close(); die(e.message); }
    console.log('  ✅ 3/5 🌐 _ust TXT ' + res.action + ' and confirmed by an independent DoH readback');
    console.log('       DNS now vouches for your hash even if every HTTP surface lies');
  } else {
    console.log('\n  ▶️  3/5 🌐 the DNS half — do this on YOUR infra:');
    for (const l of manualDnsGuide(domain, txt)) console.log('   ' + l);
    console.log('     (I will confirm it via DoH after the serving step — propagation is allowed to lag)');
  }

  // 4. publish well-known + fail-closed content-hash match. With --publish cf the adapter deploys the
  // serving worker itself (one-click); otherwise the operator publishes on ANY stack (§20.1 is a contract,
  // not a vendor) and confirms. EITHER way the live fail-closed gate below is the same.
  console.log('\n' + ceremonyMap(3));
  if (publishMode === 'cf') {
    console.log('\n  ⏳ 4/5 📡 deploying the CF serving worker (your genesis rides INSIDE it — no bucket, no origin)…');
    let pub;
    try {
      if (authMode === 'wrangler') {
        // combined auth: worker+route via wrangler OAuth; the token below stays DNS-only (smallest scope)
        // the key log rides ALONG (a verifier needs genesis AND key log) — served as a JSON array,
        // so a future rotation is an APPEND + redeploy, never a rewrite
        const w = await wranglerDeploy({ domain, genesisText: JSON.stringify(genesis), keylogText: JSON.stringify([keylog0]), witnessText: buildWitnessLog(JSON.stringify(genesis)) });
        const apex = await cfApexSteps({ domain, token: await getDnsToken(), flipProxy: !!arg("flip-proxy", false) });
        pub = { ...w, routeAction: 'wrangler', proxied: apex.proxied, flipped: apex.flipped, warnings: apex.warnings };
      } else {
        pub = await cfPublish({ domain, genesisText: JSON.stringify(genesis), keylogText: JSON.stringify([keylog0]), witnessText: buildWitnessLog(JSON.stringify(genesis)), token: process.env.CF_TOKEN || process.env.CLOUDFLARE_API_TOKEN, flipProxy: !!arg('flip-proxy', false) });
      }
    } catch (e) { rl.close(); die(e.message); }
    console.log('  ✅ worker ' + pub.script + ' + route ' + pub.route + ' (' + pub.routeAction + (pub.flipped ? ', proxy enabled on apex' : '') + ')');
    for (const w of pub.warnings) console.log('  ⚠️  ' + w);
    if (!pub.proxied) { rl.close(); die('apex is not proxied — the route cannot fire. Re-run with --flip-proxy (NOTE: puts the whole site behind CF), or enable the proxy manually and re-run.'); }
  } else {
    console.log('\n  ▶️  4/5 📡 the serving half — do this on YOUR infra:');
    for (const l of manualServingGuide(domain, outDir)) console.log('   ' + l);
    await ask('       press Enter once it is live (I will verify fail-closed, with propagation retries)… ');
  }
  // the fail-closed live gate — with propagation patience (a proxy flip needs minutes to converge)
  console.log('\n  ⏳ live gate: fetching your well-known until it serves EXACTLY this genesis (fail-closed)…');
  let liveDoc;
  try {
    liveDoc = await confirmLive({
      domain, genHash,
      onAttempt: (i, n, msg) => console.log(`     ⏳ attempt ${i}/${n} — not yet (${msg.slice(0, 80)}); DNS/proxy propagation takes minutes, waiting…`),
    });
    console.log('  ✅ 4/5 📡 the live well-known verifies and its content_hash matches YOUR genesis');
    // by-hand DNS: confirm the TXT via DoH now (same discipline as cf-api) — but WARN, never strand:
    // a slow registrar must not kill a ceremony whose binding surface already verified fail-closed.
    if (dnsMode !== 'cf-api') {
      const seen = await dohConfirmTxt({ domain, genHash, attempts: 2 });
      if (seen) console.log('  ✅ 🌐 the _ust TXT is visible via DoH and carries your hash');
      else console.log('  ⚠️  🌐 the _ust TXT is not visible via DoH yet (registrar propagation) — re-attest later:  npx @ust-protocol/cli discovery ' + domain);
    }
    // §20.1 probe (3), WARNING-level here: BINDING is fail-closed above; a serving-contract violation is
    // fixable post-hoc without redoing the ceremony. `ust discovery <domain>` re-attests all four anytime.
    try {
      const rand = `q${randomBytes(6).toString('hex')}=${randomBytes(6).toString('hex')}`;
      const baseline = JSON.stringify(liveDoc); void baseline;
      const a = await fetch(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(10000) }).then((r) => r.text());
      const probed = await fetch(`https://${domain}/.well-known/ust-genesis?${rand}`, { signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`))));
      if (probed === a) console.log('  ✅ query-robustness probe: an unknown ?query returns byte-identical bytes (§20.1)');
      else console.log('  ⚠️  §20.1 SERVING: the response VARIES with an unknown query parameter — cache-key amplification is open; fix the cache config, then `npx @ust-protocol/cli discovery ' + domain + '`');
    } catch (e) { console.log('  ⚠️  §20.1 SERVING: query-robustness probe inconclusive (' + e.message + ') — run `npx @ust-protocol/cli discovery ' + domain + '` later'); }
  } catch (e) { rl.close(); die(e.message); }

  // 5. witnesses + anchor — PREPARED here; the operator runs the exchange + anchor
  console.log('\n' + ceremonyMap(4));
  const witnesses = (arg('witness', '') || '').split(',').filter(Boolean);
  const [head, ...rest] = stageSummary({ genHash, witnesses, profile });
  console.log('\n  ▶️  5/5 ⚓ ' + head);
  for (const line of rest) console.log('       ' + line);

  for (const line of ceremonySummary({ domain, genHash, opKeyId: op.key_id, maxP, outDir, encrypted: !!pass })) console.log(line);
  rl.close();
}

// Run the dispatcher ONLY when executed directly — importing this module (regression suite / Go-binding
// harness) must not trigger the CLI or its process.exit.
const isMain = (() => { try { return process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; } })();
if (isMain) {
  const cmd = process.argv[2];
  const run = { verify: cmdVerify, canon: cmdCanon, genesis: cmdGenesis, discovery: cmdDiscovery, publish: cmdPublish, mirror: cmdMirror, stream: cmdStream }[cmd];
  if (!run) { console.error('ust — verify machine-readable state\n\n  ust verify <file|->        verify a transcript (exit 0 = VALID, 1 = not)\n  ust canon  <file|->        print canonical bytes + hash (cross-language diff)\n  ust genesis --domain <d>   run the HIGH genesis ceremony (add --publish cf for one-click serving)\n  ust discovery <domain>     attest the §20.1 serving contract (any infra)\n  ust publish cf --domain <d> --genesis <f>   deploy the CF serving adapter for an existing genesis\n  ust mirror <domain>        publish + attest a SECOND-vendor mirror (§20.1 vendor-independence)\n  ust stream <frames…>       RANGE verdict: chain · forks · completeness (needs --checkpoint for proven)\n'); process.exit(cmd ? 1 : 0); }
  run().catch((e) => die(e.message || String(e)));
}
