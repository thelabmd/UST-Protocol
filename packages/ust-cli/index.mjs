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
export const decodeInput = (raw) => {
  let s = raw.trim(); const m = '———UST(base64)———';
  if (s.includes(m)) s = s.slice(s.lastIndexOf(m) + m.length).trim();
  return s.startsWith('{') ? JSON.parse(s) : JSON.parse(Buffer.from(s.replace(/\s+/g, ''), 'base64').toString('utf8'));
};
const nowFrame = () => W.nowFrame();
// The verify context follows the record's own class: a genesis/key-log frame verifies as 'key', everything
// else as 'data'. This is why `ust verify ust-genesis` just works — no one should need to know the context.
export const contextFor = (doc) => (doc?.state?.id?.class === 'genesis' || doc?.state?.id?.class === 'key') ? 'key' : 'data';

// ─── ceremony CORE (pure, exported — a notary tool must be verifiable by tests, not just by eye) ─────────

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
export async function buildCeremony({ domain, profile = 'silver', maxP, signerRef }) {
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
  const genValue = { pub: root.pub, role: 'name-binding-root', ...(maxP ? { max_partitions: String(maxP) } : {}) };
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
  const liveDoc = decodeInput(liveText);
  if (!P.isValid(P.verify(liveDoc))) throw new Error('published document does not VERIFY');
  if (P.contentHash(liveDoc) !== genHash) throw new Error('published document is not this genesis (content_hash differs) — republish exactly the ust-genesis file');
  return liveDoc;
}

// Independent DoH readback of the _ust TXT — shared by the cf-api path AND the by-hand path, so BOTH
// roads get the same confirmation discipline (the record is confirmed by a resolver, never by the API
// that wrote it). Returns seen/not — the CALLER decides whether absence is fatal (cf-api) or a warning
// with a re-attest pointer (by-hand: registrar TTLs can be long, the ceremony must not strand the user).
export async function dohConfirmTxt({ domain, genHash, fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), attempts = 6, delayMs = 3000 }) {
  for (let i = 0; i < attempts; i++) {
    const doh = await fetchImpl(`https://cloudflare-dns.com/dns-query?name=_ust.${domain}&type=TXT`, { headers: { accept: 'application/dns-json' } }).then((r) => r.json()).catch(() => ({}));
    if ((doh.Answer || []).some((a) => (a.data || '').replace(/"/g, '').includes(genHash))) return true;
    if (i < attempts - 1) await sleep(delayMs);
  }
  return false;
}

// Cloudflare one-click: UPSERT the _ust TXT (find → PUT if present, else POST) then CONFIRM it via a
// DNS-over-HTTPS readback (idempotent + fail-closed, 9th audit #7). fetchImpl/sleep are injected so the
// regression suite exercises the update-path and the readback-failure-path with no live network.
export async function cfUpsert({ domain, txt, genHash, token, fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
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
  const seen = await dohConfirmTxt({ domain, genHash, fetchImpl, sleep });
  if (!seen) throw new Error('CF wrote the record but DoH readback did not confirm it (propagation) — re-run or verify manually');
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
    '    · immutable caching (the genesis is content-addressed):  Cache-Control: public, max-age=86400, immutable',
    '    · unknown query params must NOT change the response or its cache key (cache key = path)',
    '  examples:',
    '    · static host: upload the file to  <webroot>/.well-known/ust-genesis',
    '    · nginx:  location = /.well-known/ust-genesis { alias /srv/ust/ust-genesis;',
    '              default_type application/json; add_header Cache-Control "public, max-age=86400, immutable"; }',
  ];
}

// ─── CF one-click adapter (§20.1 CONVENIENCE path — the contract is infra-agnostic; this is ONE way) ───
// The genesis is EMBEDDED in the worker (an immutable ~1–2 KB document): no bucket, no extra credential
// scope, the worker IS the content. Query-robustness is NATIVE — the edge-cache key is the PATH, so an
// unknown ?param can never mint a new cache entry (§20.1 property, implemented at the layer that owns it).
export function buildWorkerScript(genesisText) {
  return `// ust-genesis serving worker — generated by @ust-protocol/cli (§20.1 serving contract, CF adapter)
const GENESIS = ${JSON.stringify(genesisText)};
export default {
  async fetch(req, env, ctx) {
    const u = new URL(req.url);
    if (u.pathname !== '/.well-known/ust-genesis') return new Response('not found', { status: 404 });
    if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('method not allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
    // §20.1 query-robustness: the cache key is the PATH — unknown query params never key new entries
    const key = new Request(u.origin + u.pathname, { method: 'GET' });
    let res = await caches.default.match(key);
    if (!res) {
      res = new Response(GENESIS, { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'public, max-age=86400, immutable' } });
      ctx.waitUntil(caches.default.put(key, res.clone()));
    }
    return req.method === 'HEAD' ? new Response(null, { headers: res.headers }) : res;
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
export function buildWranglerProject({ domain, genesisText }) {
  return {
    'worker.mjs': buildWorkerScript(genesisText),
    'wrangler.toml': [
      `name = "ust-genesis-${domain.replaceAll('.', '-')}"`,
      'main = "worker.mjs"',
      'compatibility_date = "2026-01-01"',
      'workers_dev = false',
      `routes = [{ pattern = "${domain}/.well-known/ust-genesis*", zone_name = "${domain}" }]`,
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
export async function wranglerDeploy({ domain, genesisText, execImpl = null, writeImpl = null }) {
  const doc = decodeInput(genesisText);
  if (!P.isValid(P.verify(doc))) throw new Error('refusing to publish: the genesis does not VERIFY');
  const files = buildWranglerProject({ domain, genesisText });
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
  return { genHash: P.contentHash(doc), script: `ust-genesis-${domain.replaceAll('.', '-')}`, route: `${domain}/.well-known/ust-genesis*`, dir };
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
export async function cfPublish({ domain, genesisText, token, flipProxy = false, fetchImpl = fetch }) {
  if (!token) throw new Error('cf adapter needs CF_TOKEN (Workers Scripts:Edit + Workers Routes:Edit + DNS:Edit for this zone) — or split the scopes: `--auth wrangler` + a DNS-only token (' + CF_DNS_TOKEN_URL + ')');
  const doc = decodeInput(genesisText);
  if (!P.isValid(P.verify(doc))) throw new Error('refusing to publish: the genesis does not VERIFY');
  const genHash = P.contentHash(doc);
  const cf = (path, init) => fetchImpl('https://api.cloudflare.com/client/v4' + path, { ...init, headers: { Authorization: 'Bearer ' + token, ...(init?.headers) } }).then((r) => r.json());

  const zone = (await cf(`/zones?name=${domain}`)).result?.[0];
  if (!zone) throw new Error('CF zone not found / token cannot see ' + domain);
  const accountId = zone.account?.id;
  if (!accountId) throw new Error('zone carries no account id — token needs zone read access');

  // 1. worker script (PUT = create-or-replace, idempotent; module syntax)
  const script = `ust-genesis-${domain.replaceAll('.', '-')}`;
  const form = new FormData();
  form.append('metadata', new Blob([JSON.stringify({ main_module: 'worker.mjs', compatibility_date: '2026-01-01' })], { type: 'application/json' }), 'metadata');
  form.append('worker.mjs', new Blob([buildWorkerScript(genesisText)], { type: 'application/javascript+module' }), 'worker.mjs');
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

  // (1) well-known: fetch → VERIFY the transcript → content_hash (baseline bytes kept for probe 3)
  let baseline = null, hash = null;
  try {
    const r = await get(url);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    baseline = await r.text();
    const doc = decodeInput(baseline);
    if (!P.isValid(P.verify(doc))) throw new Error('published document does not VERIFY');
    hash = P.contentHash(doc);
    if (expectHash && hash !== expectHash) throw new Error(`content_hash differs from --expect (${hash} ≠ ${expectHash})`);
    checks.push({ id: 'well-known verifies (§14, fail-closed)', status: 'pass', detail: hash });
  } catch (e) {
    checks.push({ id: 'well-known verifies (§14, fail-closed)', status: 'fail', detail: e.message });
    return { hash: null, checks, verdict: verdictOf(checks) }; // nothing downstream is meaningful without (1)
  }

  // (2) DNS pair: _ust TXT must carry THIS hash when present; absent = NOT ATTESTED (the pair is standard,
  // plain-DNS absence is reported, mismatch is a hard violation)
  try {
    const doh = await get(`https://cloudflare-dns.com/dns-query?name=_ust.${domain}&type=TXT`, { headers: { accept: 'application/dns-json' } }).then((r) => r.json());
    const txts = (doh.Answer || []).map((a) => (a.data || '').replace(/"/g, ''));
    const ours = txts.filter((t) => t.startsWith('ust-genesis='));
    if (!ours.length) checks.push({ id: 'DNS record (_ust TXT) matches', status: 'skip', detail: 'no _ust TXT found — pair NOT ATTESTED (publish ust-genesis=<content_hash>)' });
    else if (ours.some((t) => t === 'ust-genesis=' + hash)) checks.push({ id: 'DNS record (_ust TXT) matches', status: 'pass', detail: '_ust.' + domain });
    else checks.push({ id: 'DNS record (_ust TXT) matches', status: 'fail', detail: `TXT carries a DIFFERENT hash (${ours[0]}) — a stale or hijacked record` });
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
      const d = decodeInput(t);
      if (!P.isValid(P.verify(d))) throw new Error('mirror document does not VERIFY');
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
  throw new Error(`could not confirm the published well-known after ${attempts} attempts (~${Math.round(attempts * delayMs / 60000)} min): ${last.message}\n  authoritative NOT granted. DNS/proxy propagation can take a few minutes — your artifacts are ALREADY written and the deployment may be fine; verify later with:  ust discovery ${domain} --expect ${genHash}`);
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
    '                   authoritative:  ust verify <doc> --genesis ust-genesis --keylog ust-keylog-0 --no-fork-confirmed',
    '  TOP    ⏳ later — anchor the stream (e.g. bitcoin-ots): provable TIME + provable completeness',
    '',
    '  ➡️  next moves',
    "  1. operational-key.b64 → your producer's signing-key secret (an env var of YOUR naming), then DELETE the file",
    '  2. revoke the ceremony credentials (wrangler logout + the DNS token)',
    `  3. re-attest the serving contract anytime:  ust discovery ${domain}`,
    '  4. HIGH: run the witness exchange + serve the key log    5. TOP: queue the anchor',
    '  ══════════════════════════════════════════════',
  ];
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
  if (!src) die('usage: ust verify <file | - for stdin> [--context data|key] [--genesis <file> --keylog <file[,file…]> [--no-fork-confirmed]]');
  const raw = src === '-' ? readFileSync(0, 'utf8') : readFileSync(src, 'utf8');
  let doc; try { doc = decodeInput(raw); } catch (e) { die('not a UST blob/base64/json: ' + e.message); }

  // optional HIGH resolution: the capacity grant flows FROM authority resolution (rc.12), never raw
  let opts = { context: arg('context', null) || contextFor(doc) };
  const genesisPath = arg('genesis', null);
  const noFork = !!arg('no-fork-confirmed', false);
  if (genesisPath && genesisPath !== true) {
    let genesisDoc, keylogDocs;
    try {
      genesisDoc = decodeInput(readFileSync(genesisPath, 'utf8'));
      const kl = arg('keylog', null);
      keylogDocs = (kl && kl !== true ? String(kl).split(',') : []).map((p) => decodeInput(readFileSync(p, 'utf8')));
    } catch (e) { die('could not read the resolution inputs: ' + e.message); }
    const auth = P.resolveAuthority(doc, { genesis: genesisDoc, keylog: keylogDocs, noForkConfirmed: noFork });
    if (auth.error) die('authority resolution failed: ' + auth.error + (auth.detail ? ' — ' + auth.detail : ''));
    opts = { ...opts, genesis: genesisDoc, keylog: keylogDocs, noForkConfirmed: noFork, capacity: auth.capacity };
  }

  const r = P.verify(doc, opts);
  console.log(r.result + (r.error ? '  (' + r.error + (r.detail ? ' — ' + r.detail : '') + ')' : ''));
  if (P.isValid(r)) {
    const tier = r.result.split(':')[1] ?? 'LIGHT';
    console.log('  identity : ' + r.identity.strength + ' (mode ' + r.identity.mode + ')  ' + (r.publisher ? 'publisher ' + r.publisher : 'publisher_claimed ' + r.publisher_claimed));
    console.log('  time     : ' + r.time.strength + '/' + r.time.status + '   completeness: ' + r.completeness);
    console.log('  ust_id   : ' + r.ust_id + '   class ' + r.class + '   content_hash ' + r.content_hash);
    console.log('  tier     : ' + ['LIGHT', 'HIGH', 'TOP'].map((t) => (t === tier ? `[${t}]` : ` ${t} `)).join('→'));
    if (tier === 'LIGHT' && !genesisPath) {
      console.log('\n  ✅ this is the EXPECTED result for a lone document — it proves the file is signed and');
      console.log('     intact under the key it carries. HIGH is a property of RESOLUTION, not of the file:');
      console.log('     ust verify <doc> --genesis <ust-genesis> --keylog <ust-keylog-0> --no-fork-confirmed');
    } else if (tier === 'LIGHT' && genesisPath && !noFork) {
      console.log('\n  ℹ️  resolution ran but the name is not authoritative WITHOUT the no-fork witness check.');
      console.log('     Once your witness exchange confirms no rival genesis exists, add: --no-fork-confirmed');
    } else if (tier === 'HIGH') {
      console.log('\n  🏛  the NAME is authoritative: genesis→key-log resolved' + (noFork ? ' (+ no-fork asserted by YOU — that assertion is your operator duty)' : ''));
      console.log('     TOP is next: anchor the stream (provable time + completeness)');
    }
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

// ─── ust discovery <domain> — §20.1 compliance attestation (any infra; properties, not mechanisms) ────
async function cmdDiscovery() {
  const domain = process.argv[3];
  if (!domain || domain.startsWith('--')) die('usage: ust discovery <domain> [--mirror url,url] [--expect sha256:…]   # attest the §20.1 serving contract');
  const mirrors = (arg('mirror', '') || '').split(',').filter(Boolean);
  const expectHash = arg('expect', null);
  const { hash, checks, verdict } = await attestDiscovery({ domain, mirrors, expectHash });
  const mark = { pass: '✅', fail: '❌', skip: '⬜' };
  for (const c of checks) console.log(`  ${mark[c.status]}  ${c.id}${c.detail ? '  (' + c.detail + ')' : ''}`);
  console.log(`\n  DISCOVERY CONFORMANCE (§20.1): ${verdict}${hash ? '   genesis ' + hash : ''}`);
  if (verdict === 'PARTIAL') {
    // targeted hints (rc.8): name ONLY what was actually skipped — never advise republishing what already passed
    console.log('  PARTIAL = no violation found, but unchecked properties remain:');
    for (const c of checks.filter((x) => x.status === 'skip')) {
      if (c.id.startsWith('DNS record')) console.log('    → publish the _ust TXT (ust-genesis=<content_hash>) and re-run');
      else if (c.id.startsWith('vendor-independence')) console.log(`    → declare an independent mirror:  ust discovery ${domain} --mirror <url>`);
      else console.log('    → ' + c.id + ' — ' + c.detail);
    }
  }
  process.exit(verdict === 'FAILED' ? 1 : 0);
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

  let r;
  if (arg('auth', null) === 'wrangler') {
    // COMBINED flow: worker+route ride wrangler's OAuth (browser login — no workers scopes on any token);
    // the API token shrinks to Zone.DNS:Edit for the apex steps.
    let w; try { w = await wranglerDeploy({ domain, genesisText }); } catch (e) { die(e.message); }
    console.log('  ✓ worker ' + w.script + ' deployed via wrangler OAuth (genesis embedded, ' + w.genHash + ')');
    console.log('  ✓ route ' + w.route + ' (from wrangler.toml)');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    let apex; try { apex = await cfApexSteps({ domain, token: await resolveDnsToken((q) => rl.question(q)), flipProxy }); }
    catch (e) { rl.close(); die(e.message); }
    rl.close();
    r = { ...w, routeAction: 'wrangler', proxied: apex.proxied, flipped: apex.flipped, warnings: apex.warnings };
  } else {
    const token = process.env.CF_TOKEN || process.env.CLOUDFLARE_API_TOKEN;
    try { r = await cfPublish({ domain, genesisText, token, flipProxy }); } catch (e) { die(e.message); }
    console.log('  ✓ worker ' + r.script + ' deployed (genesis embedded, ' + r.genHash + ')');
    console.log('  ✓ route ' + r.route + ' ' + r.routeAction);
  }
  if (r.flipped) console.log(`  ✓ proxy enabled on ${r.flipped} apex record${r.flipped > 1 ? 's' : ''}`);
  for (const w of r.warnings) console.log('  ⚠  ' + w);
  if (!r.proxied) { console.log('\n  NOT LIVE YET — the apex is not proxied; nothing to attest.'); process.exit(1); }
  // fail-closed: deployment is only DONE when the live surface attests (§20.1 probes)
  const mirrors = (arg('mirror', '') || '').split(',').filter(Boolean);
  const a = await attestDiscovery({ domain, mirrors, expectHash: r.genHash });
  const mark = { pass: '✓', fail: '✗', skip: '–' };
  for (const c of a.checks) console.log(`  ${mark[c.status]}  ${c.id}${c.detail ? '  (' + c.detail + ')' : ''}`);
  console.log(`\n  DISCOVERY CONFORMANCE (§20.1): ${a.verdict}`);
  process.exit(a.verdict === 'FAILED' ? 1 : 0);
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
  console.log(`\n  ⚙️  profile ${profile} · max_partitions ${maxP ?? '(floor 64)'} · road ${publishMode === 'cf' ? 'cloudflare one-click' : 'by hand'}`);
  console.log(`      files → ${outDir === '.' ? process.cwd() : outDir}  (override with --out)`);
  // one token, asked ONCE at first need — steps 3 and 4 share it (never a double paste-prompt)
  let dnsTokenMemo = null;
  const getDnsToken = async () => (dnsTokenMemo ??= await resolveDnsToken(ask));

  // 1–2. root key + genesis + key-log[0], all self-checked (fail-closed) inside buildCeremony
  let built; try { built = await buildCeremony({ domain, profile, maxP, signerRef }); }
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
    while (pass.length < 8) pass = await ask('     set the passphrase (≥8 chars): ');
  }
  const backup = pass ? encryptKey(pkcs8, pass) : pkcs8.toString('base64');
  writeFileSync(`${outDir}/genesis-key${pass ? '.enc' : ''}.b64`, backup);
  // operational key = the WARM daily signer. Written PLAIN base64 PKCS8 because the
  // producer loads it non-interactively from its signing-key env. It is NOT cold-store:
  // move it into the producer's secret store, then delete this file — never commit it.
  writeFileSync(`${outDir}/operational-key.b64`, opPkcs8.toString('base64'));
  writeFileSync(`${outDir}/ust-genesis`, JSON.stringify(genesis));
  writeFileSync(`${outDir}/ust-keylog-0`, JSON.stringify(keylog0));
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
      res = await cfUpsert({ domain, txt, genHash, token: dnsToken });
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
        const w = await wranglerDeploy({ domain, genesisText: JSON.stringify(genesis) });
        const apex = await cfApexSteps({ domain, token: await getDnsToken(), flipProxy: !!arg("flip-proxy", false) });
        pub = { ...w, routeAction: 'wrangler', proxied: apex.proxied, flipped: apex.flipped, warnings: apex.warnings };
      } else {
        pub = await cfPublish({ domain, genesisText: JSON.stringify(genesis), token: process.env.CF_TOKEN || process.env.CLOUDFLARE_API_TOKEN, flipProxy: !!arg('flip-proxy', false) });
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
      else console.log('  ⚠️  🌐 the _ust TXT is not visible via DoH yet (registrar propagation) — re-attest later:  ust discovery ' + domain);
    }
    // §20.1 probe (3), WARNING-level here: BINDING is fail-closed above; a serving-contract violation is
    // fixable post-hoc without redoing the ceremony. `ust discovery <domain>` re-attests all four anytime.
    try {
      const rand = `q${randomBytes(6).toString('hex')}=${randomBytes(6).toString('hex')}`;
      const baseline = JSON.stringify(liveDoc); void baseline;
      const a = await fetch(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(10000) }).then((r) => r.text());
      const probed = await fetch(`https://${domain}/.well-known/ust-genesis?${rand}`, { signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`))));
      if (probed === a) console.log('  ✅ query-robustness probe: an unknown ?query returns byte-identical bytes (§20.1)');
      else console.log('  ⚠️  §20.1 SERVING: the response VARIES with an unknown query parameter — cache-key amplification is open; fix the cache config, then `ust discovery ' + domain + '`');
    } catch (e) { console.log('  ⚠️  §20.1 SERVING: query-robustness probe inconclusive (' + e.message + ') — run `ust discovery ' + domain + '` later'); }
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
  const run = { verify: cmdVerify, canon: cmdCanon, genesis: cmdGenesis, discovery: cmdDiscovery, publish: cmdPublish }[cmd];
  if (!run) { console.error('ust — verify machine-readable state\n\n  ust verify <file|->        verify a transcript (exit 0 = VALID, 1 = not)\n  ust canon  <file|->        print canonical bytes + hash (cross-language diff)\n  ust genesis --domain <d>   run the HIGH genesis ceremony (add --publish cf for one-click serving)\n  ust discovery <domain>     attest the §20.1 serving contract (any infra)\n  ust publish cf --domain <d> --genesis <f>   deploy the CF serving adapter for an existing genesis\n'); process.exit(cmd ? 1 : 0); }
  run().catch((e) => die(e.message || String(e)));
}
