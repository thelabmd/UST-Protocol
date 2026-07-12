// SPDX-License-Identifier: Apache-2.0
// CLI ceremony regression — the 9th audit's seven points, frozen as tests so a TENTH audit can't silently
// reintroduce the ninth defect. Each check name IS the guarantee it locks. Runs the exported ceremony core
// (no live network: CF fetch + DoH readback are injected). Prints `PASS n FAIL n NOTES n` like conformance.
import { readFileSync } from 'node:fs';
import * as C from './index.mjs';
import * as P from 'ust-protocol';
import * as W from '@ust-protocol/web-signer';

let pass = 0, fail = 0, note = 0; const fails = [];
const check = (id, ok, d) => { if (ok) pass++; else { fail++; fails.push(id + (d ? ' — ' + d : '')); } };
const threw = async (fn) => { try { await fn(); return false; } catch { return true; } };
const DOMAIN = 'genesis-test.invalid';   // RFC 2606 test name — no real domain touched

// A CF mock: a zone that exists, an existing/absent _ust record, and a DoH readback that confirms-or-not.
const mkCf = ({ existing, dohConfirms, genHash }) => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, method: init?.method || 'GET' });
    if (url.includes('/zones?name=')) return { json: async () => ({ result: [{ id: 'zone1' }] }) };
    if (url.includes('/dns_records?type=TXT')) return { json: async () => ({ result: existing ? [{ id: 'rec1' }] : [] }) };
    if (url.includes('cloudflare-dns.com')) return { json: async () => (dohConfirms ? { Answer: [{ data: `"ust-genesis=${genHash}"` }] } : { Answer: [] }) };
    if (url.includes('/dns_records')) return { json: async () => ({ success: true }) };   // POST (create) or PUT (update)
    return { json: async () => ({}) };
  };
  return { fetchImpl, calls };
};

// ── 1. tiers are about their OWN thing (owner 2026-07-12): gold IS hardware — the CLI cannot drive a
// hardware signer yet, so gold REFUSES honestly (the old shape — software key + a warning, --signer
// merely silencing it — sold software as gold). A refusal names the silver path + §12.1 upgrade.
{
  let msg = '';
  try { await C.buildCeremony({ domain: DOMAIN, profile: 'gold' }); } catch (e) { msg = e.message; }
  check('gold_is_hardware_only_and_refuses', msg.includes('HARDWARE') && msg.includes('silver') && msg.includes('supersession'));
  let msg2 = '';
  try { await C.buildCeremony({ domain: DOMAIN, profile: 'gold', signerRef: 'pkcs11:slot0' }); } catch (e) { msg2 = e.message; }
  check('gold_signer_flag_cannot_fake_hardware', msg2.includes('no hardware driver'));
  const s = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  check('silver_builds_clean_no_false_assurance', s.warnings.length === 0 && !!s.genHash);
}

// ── 2. outputs_self_verify — both outputs verify, and the self-check is a REAL gate (tampering breaks it)
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  check('outputs_self_verify', P.isValid(P.verify(g.genesis)) && P.isValid(P.verify(g.keylog0, { context: 'key' })));
  const tampered = JSON.parse(JSON.stringify(g.genesis));
  tampered.state.data.genesis.value.role = 'tampered';
  check('self_check_is_fail_closed', !P.isValid(P.verify(tampered)));   // the gate buildCeremony relies on actually bites
}

// ── 2b. the CLI's own context-detect makes `ust verify` VALID on both outputs (the promise "verify them")
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  check('genesis_verifies_via_cli_context', C.contextFor(g.genesis) === 'key' && P.isValid(P.verify(g.genesis, { context: C.contextFor(g.genesis) })));
  check('keylog_verifies_via_cli_context', C.contextFor(g.keylog0) === 'key' && P.isValid(P.verify(g.keylog0, { context: C.contextFor(g.keylog0) })));
  check('observation_defaults_to_data_context', C.contextFor({ state: { id: { class: 'observation' } } }) === 'data');
}

// ── 3. backup_is_not_ust — the encrypted key backup must NOT parse as a UST (so nobody runs `ust verify` on it)
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const enc = C.encryptKey(g.pkcs8, 'test-passphrase-12');
  let parsedAsUst = false;
  try { const o = JSON.parse(Buffer.from(enc, 'base64').toString('utf8')); parsedAsUst = !!(o && o.ust); } catch { parsedAsUst = false; }
  check('backup_is_not_ust', !parsedAsUst);
}

// ── 4. well_known_content_hash_mismatch_fails — publishing the wrong genesis fails closed; the right one passes
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const other = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });   // different key ⇒ different content_hash
  check('well_known_content_hash_mismatch_fails', await threw(() => C.checkPublished(JSON.stringify(other.genesis), g.genHash)));
  check('well_known_correct_doc_passes', !(await threw(() => C.checkPublished(JSON.stringify(g.genesis), g.genHash))));
}

// ── 5. cf_existing_record_uses_update — an existing _ust record is PUT (update), an absent one is POST (create)
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const up = mkCf({ existing: true, dohConfirms: true, genHash: g.genHash });
  const rU = await C.cfUpsert({ domain: DOMAIN, txt: `ust-genesis=${g.genHash}`, genHash: g.genHash, token: 'x', fetchImpl: up.fetchImpl, sleep: async () => {} });
  const putCall = up.calls.find((c) => c.url.includes('/dns_records/rec1'));
  check('cf_existing_record_uses_update', rU.action === 'updated' && !!putCall && putCall.method === 'PUT');
  const cr = mkCf({ existing: false, dohConfirms: true, genHash: g.genHash });
  const rC = await C.cfUpsert({ domain: DOMAIN, txt: `ust-genesis=${g.genHash}`, genHash: g.genHash, token: 'x', fetchImpl: cr.fetchImpl, sleep: async () => {} });
  const postCall = cr.calls.find((c) => c.method === 'POST' && c.url.endsWith('/dns_records'));
  check('cf_absent_record_uses_create', rC.action === 'created' && !!postCall);
}

// ── 6. doh_readback_failure_fails — a write CF accepts but DoH never confirms must fail closed (no false success)
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const nc = mkCf({ existing: false, dohConfirms: false, genHash: g.genHash });
  check('doh_readback_failure_fails', await threw(() => C.cfUpsert({ domain: DOMAIN, txt: `ust-genesis=${g.genHash}`, genHash: g.genHash, token: 'x', fetchImpl: nc.fetchImpl, sleep: async () => {} })));
  check('cf_missing_token_fails', await threw(() => C.cfUpsert({ domain: DOMAIN, txt: 'x', genHash: g.genHash, token: '', fetchImpl: nc.fetchImpl, sleep: async () => {} })));
  // UPDATE patience (2nd live ceremony): an updated record waits through a full resolver-TTL window
  // (24 attempts, narrated) and the failure text explains TTL + the idempotent re-run — never a bare
  // "re-run or verify manually" that leaves the operator guessing.
  const upd = mkCf({ existing: true, dohConfirms: false, genHash: g.genHash });
  const seenAttempts = [];
  let updMsg = '';
  try { await C.cfUpsert({ domain: DOMAIN, txt: `ust-genesis=${g.genHash}`, genHash: g.genHash, token: 'x', fetchImpl: upd.fetchImpl, sleep: async () => {}, onAttempt: (i) => seenAttempts.push(i) }); }
  catch (e) { updMsg = e.message; }
  check('doh_update_waits_full_ttl_window', seenAttempts.length === 24);
  check('doh_failure_explains_ttl_and_rerun', updMsg.includes('TTL') && updMsg.includes('RE-RUN') && updMsg.includes('idempotent'));
}

// ── 7. witness_stage_does_not_claim_execution — the summary PREPARES the stage, never claims it ran
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const lines = C.stageSummary({ genHash: g.genHash, witnesses: [], profile: 'silver' }).join(' ');
  const prepared = lines.includes('STAGE PREPARED (not executed');
  const falseClaim = /verified \d+ witnesses|witnesses verified|✓[^\n]*anchored|anchored to bitcoin/i.test(lines);
  check('witness_stage_does_not_claim_execution', prepared && !falseClaim);
  // belt + suspenders: no affirmative-success overclaim shape may creep into the CLI source itself
  const src = readFileSync(new URL('./index.mjs', import.meta.url), 'utf8');
  const forbidden = [/verified \d+ witnesses/i, /byte-for-byte match/i, /✓[^\n]*anchored to bitcoin/i, /queue anchor[^\n]*✓/i];
  const hit = forbidden.filter((re) => re.test(src)).map((re) => re.source);
  check('source_has_no_affirmative_overclaim', hit.length === 0, hit.join(' | '));
}

// ── 8. operational_key_is_exported_and_usable — the ceremony MUST hand back the warm
// signer's PKCS#8 (opPkcs8), and it must round-trip exactly as the producer loads it
// (Buffer.from(b64,'base64') → import Ed25519 → sign). A stranded op key = a dead genesis.
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  check('operational_key_exported', Buffer.isBuffer(g.opPkcs8) && g.opPkcs8.length > 0);
  let signs = false;
  try {
    const der = Buffer.from(g.opPkcs8.toString('base64'), 'base64'); // exactly the UST_ENGINE_SK path
    const priv = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
    const s = await crypto.subtle.sign({ name: 'Ed25519' }, priv, new Uint8Array([1, 2, 3]));
    signs = s.byteLength === 64; // Ed25519 signature width
  } catch { signs = false; }
  check('operational_key_round_trips_as_producer_signer', signs);
}

// ── 9. discovery attestation (§20.1) — the four probes are REAL gates and the verdict is honest
// (ATTESTED only when everything ran and passed; a skip is PARTIAL, never a silent pass).
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const bytes = JSON.stringify(g.genesis);
  // a mock publisher: well-known + optional TXT + optional mirror; `busted` varies bytes per-query.
  const klArr9 = JSON.stringify([g.keylog0]);
  const mkPub = ({ txtHash, busted, mirrorBytes, keylog = klArr9 } = {}) => async (url) => {
    const u = String(url);
    if (u.includes('cloudflare-dns.com')) return { ok: true, json: async () => (txtHash ? { Answer: [{ data: `"ust-genesis=${txtHash}"` }] } : {}) };
    if (u.includes('mirror.example')) return mirrorBytes ? { ok: true, text: async () => mirrorBytes } : { ok: false, status: 404, text: async () => '' };
    if (u.includes('/.well-known/ust-keylog')) return keylog ? { ok: true, text: async () => keylog } : { ok: false, status: 404, text: async () => '' };
    if (u.includes('/.well-known/ust-genesis')) {
      const q = u.includes('?');
      return { ok: true, text: async () => (busted && q ? bytes + '\n' : bytes) };
    }
    return { ok: false, status: 404, text: async () => '' };
  };

  // full pass: TXT matches + robust + mirror matches ⇒ ATTESTED, zero skips
  const full = await C.attestDiscovery({ domain: DOMAIN, mirrors: ['https://mirror.example/g'], fetchImpl: mkPub({ txtHash: g.genHash, mirrorBytes: bytes }) });
  check('discovery_full_attests', full.verdict === 'ATTESTED' && full.hash === g.genHash);

  // query-bust: bytes vary with an unknown ?param ⇒ FAILED (the §20.1 property is a real gate)
  const bust = await C.attestDiscovery({ domain: DOMAIN, fetchImpl: mkPub({ txtHash: g.genHash, busted: true }) });
  check('discovery_query_bust_fails', bust.verdict === 'FAILED' && bust.checks.some((c) => c.id.startsWith('query-robustness') && c.status === 'fail'));

  // stale/hijacked TXT: a DIFFERENT hash in _ust ⇒ FAILED (never “present = fine”)
  const stale = await C.attestDiscovery({ domain: DOMAIN, fetchImpl: mkPub({ txtHash: 'sha256:' + 'ff'.repeat(32) }) });
  check('discovery_stale_txt_fails', stale.verdict === 'FAILED');

  // absent TXT + no mirror: no violation, but PARTIAL — unchecked properties never attest
  const partial = await C.attestDiscovery({ domain: DOMAIN, fetchImpl: mkPub({ keylog: null }) });
  check('discovery_partial_is_honest', partial.verdict === 'PARTIAL' && partial.checks.filter((c) => c.status === 'skip').length === 3);

  // mirror carrying a DIFFERENT genesis ⇒ FAILED (mirrors are availability, the hash decides)
  const other = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const wrong = await C.attestDiscovery({ domain: DOMAIN, mirrors: ['https://mirror.example/g'], fetchImpl: mkPub({ txtHash: g.genHash, mirrorBytes: JSON.stringify(other.genesis) }) });
  check('discovery_wrong_mirror_fails', wrong.verdict === 'FAILED');

  // broken well-known short-circuits: nothing downstream is meaningful without (1)
  const dead = await C.attestDiscovery({ domain: DOMAIN, fetchImpl: async () => ({ ok: false, status: 402, text: async () => '' }) });
  check('discovery_dead_well_known_fails_closed', dead.verdict === 'FAILED' && dead.hash === null && dead.checks.length === 1);
}

// ── 10. CF publish adapter (§20.1 convenience path) — fail-closed before ANY write, idempotent route,
// explicit proxy policy, and the worker embeds the EXACT genesis bytes with a path-keyed cache.
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const bytes = JSON.stringify(g.genesis);

  // the generated worker: exact-bytes embedding + the two §20.1 serving properties in the source
  const src = C.buildWorkerScript(bytes);
  check('worker_embeds_exact_bytes', src.includes(JSON.stringify(bytes)));
  // STATELESS (3rd live ceremony): the Cache API survived worker redeploys and kept serving the PREVIOUS
  // genesis for its 24 h TTL. No state ⇒ the whole staleness bug-class is gone; max-age is BOUNDED so
  // downstream caches converge in the same window as the DNS TTL.
  check('worker_is_stateless_no_cache_api', !src.includes('caches.default'));
  check('worker_max_age_is_bounded', src.includes('max-age=300') && !src.includes('max-age=86400'));
  check('worker_get_head_only', src.includes("allow: 'GET, HEAD'"));
  // browser verifiers auto-resolve the discovery pair cross-origin — public identity data is CORS-open
  check('worker_is_cors_open', src.includes("'access-control-allow-origin': '*'"));

  // a CF API mock: zone (with account), script PUT, routes list/POST/PUT, dns records, ssl setting
  const mkApi = ({ proxied, routeExists, ssl = 'full' } = {}) => {
    const calls = [];
    const fetchImpl = async (url, init) => {
      const u = String(url), m = init?.method || 'GET';
      calls.push({ u, m });
      if (u.includes('/zones?name=')) return { json: async () => ({ result: [{ id: 'z1', account: { id: 'acc1' } }] }) };
      if (u.includes('/workers/scripts/')) return { json: async () => ({ success: true }) };
      if (u.includes('/workers/routes') && m === 'GET') return { json: async () => ({ result: routeExists ? [{ id: 'r1', pattern: `${DOMAIN}/.well-known/ust-genesis*` }] : [] }) };
      if (u.includes('/workers/routes')) return { json: async () => ({ success: true }) };
      if (u.includes('/dns_records?name=')) return { json: async () => ({ result: [{ id: 'd1', type: 'A', proxied }] }) };
      if (u.includes('/dns_records/')) return { json: async () => ({ success: true }) };
      if (u.includes('/settings/ssl')) return { json: async () => ({ result: { value: ssl } }) };
      return { json: async () => ({}) };
    };
    return { fetchImpl, calls };
  };

  // fail-closed: an invalid genesis never reaches the network
  const tam = JSON.parse(bytes); tam.state.data.genesis.value.pub = 'AAAA' + tam.state.data.genesis.value.pub.slice(4);
  const net = mkApi({ proxied: true });
  check('cfpublish_invalid_genesis_never_touches_network', await threw(() => C.cfPublish({ domain: DOMAIN, genesisText: JSON.stringify(tam), token: 'x', fetchImpl: net.fetchImpl })) && net.calls.length === 0);
  check('cfpublish_missing_token_fails', await threw(() => C.cfPublish({ domain: DOMAIN, genesisText: bytes, token: '', fetchImpl: net.fetchImpl })));

  // proxied zone, no prior route → script PUT + route POST, proxied:true, no PATCH
  const a = mkApi({ proxied: true });
  const r1 = await C.cfPublish({ domain: DOMAIN, genesisText: bytes, token: 'x', fetchImpl: a.fetchImpl });
  check('cfpublish_creates_route_when_absent', r1.routeAction === 'created' && r1.proxied && r1.flipped === 0);
  check('cfpublish_uploads_module_worker', a.calls.some((c) => c.u.includes('/workers/scripts/ust-genesis-') && c.m === 'PUT'));

  // existing route → PUT (update), idempotent — never a duplicate POST
  const b = mkApi({ proxied: true, routeExists: true });
  const r2 = await C.cfPublish({ domain: DOMAIN, genesisText: bytes, token: 'x', fetchImpl: b.fetchImpl });
  check('cfpublish_updates_existing_route', r2.routeAction === 'updated' && !b.calls.some((c) => c.u.endsWith('/workers/routes') && c.m === 'POST'));

  // grey apex WITHOUT --flip-proxy → warning + NOT proxied + NO dns mutation (explicit blast-radius policy)
  const c1 = mkApi({ proxied: false });
  const r3 = await C.cfPublish({ domain: DOMAIN, genesisText: bytes, token: 'x', fetchImpl: c1.fetchImpl });
  check('cfpublish_grey_apex_reports_not_mutates', !r3.proxied && r3.warnings.some((w) => w.includes('--flip-proxy')) && !c1.calls.some((c) => c.m === 'PATCH'));

  // grey apex WITH flipProxy → PATCH fired + proxied
  const c2 = mkApi({ proxied: false });
  const r4 = await C.cfPublish({ domain: DOMAIN, genesisText: bytes, token: 'x', flipProxy: true, fetchImpl: c2.fetchImpl });
  check('cfpublish_flip_proxy_patches_apex', r4.proxied && r4.flipped === 1 && c2.calls.some((c) => c.m === 'PATCH'));

  // flexible SSL on a live (proxied) zone → loud loop warning
  const d1 = mkApi({ proxied: true, ssl: 'flexible' });
  const r5 = await C.cfPublish({ domain: DOMAIN, genesisText: bytes, token: 'x', fetchImpl: d1.fetchImpl });
  check('cfpublish_flexible_ssl_warns', r5.warnings.some((w) => w.toLowerCase().includes('flexible')));
}

// ── 11. combined auth (wrangler OAuth + DNS-only token) — the scope split is real: the wrangler path
// never needs workers scopes on a token, and the small-token path degrades gracefully where it cannot see.
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const bytes = JSON.stringify(g.genesis);

  // the generated project: exact worker bytes + the route riding wrangler.toml (zone-bound, no workers_dev)
  const proj = C.buildWranglerProject({ domain: DOMAIN, genesisText: bytes });
  check('wrangler_project_worker_is_exact', proj['worker.mjs'] === C.buildWorkerScript(bytes));
  check('wrangler_project_route_in_toml', proj['wrangler.toml'].includes(`${DOMAIN}/.well-known/ust-genesis*`) && proj['wrangler.toml'].includes(`zone_name = "${DOMAIN}"`) && proj['wrangler.toml'].includes('workers_dev = false'));

  // deploy: files written, exec runs in the project dir, hash returned; a failing exec names the login fix
  const written = []; let ranIn = null;
  const ok = await C.wranglerDeploy({ domain: DOMAIN, genesisText: bytes, writeImpl: (p, c) => written.push(p), execImpl: async (cwd) => { ranIn = cwd; return 0; } });
  check('wrangler_deploy_writes_and_runs', written.length === 2 && ranIn !== null && ok.genHash === g.genHash);
  check('wrangler_deploy_failure_names_login', await threw(() => C.wranglerDeploy({ domain: DOMAIN, genesisText: bytes, writeImpl: () => {}, execImpl: async () => 1 })));

  // least-privilege pin: the prescribed login is the MINIMAL 5-scope consent, never the default 28 —
  // and the failure message carries it (a user should never be steered to the broad grant).
  check('wrangler_login_is_minimal_scoped', C.WRANGLER_LOGIN_CMD.includes('--scopes') && ['account:read', 'user:read', 'workers_scripts:write', 'workers_routes:write', 'zone:read'].every((s) => C.WRANGLER_LOGIN_CMD.includes(s)) && !C.WRANGLER_LOGIN_CMD.includes('d1:') && !C.WRANGLER_LOGIN_CMD.includes('pages:'));
  try { await C.wranglerDeploy({ domain: DOMAIN, genesisText: bytes, writeImpl: () => {}, execImpl: async () => 1 }); }
  catch (e) { check('wrangler_failure_message_carries_scoped_login', e.message.includes(C.WRANGLER_LOGIN_CMD)); }

  // fail-closed: an invalid genesis never reaches disk OR exec
  const tam = JSON.parse(bytes); tam.state.data.genesis.value.pub = 'AAAA' + tam.state.data.genesis.value.pub.slice(4);
  const w2 = []; let ran2 = false;
  check('wrangler_invalid_genesis_never_writes', await threw(() => C.wranglerDeploy({ domain: DOMAIN, genesisText: JSON.stringify(tam), writeImpl: (p) => w2.push(p), execImpl: async () => { ran2 = true; return 0; } })) && w2.length === 0 && !ran2);

  // the prefilled token page: DNS:edit preselected — the deep-link shape is pinned
  check('dns_token_url_is_prefilled', C.CF_DNS_TOKEN_URL.startsWith('https://dash.cloudflare.com/profile/api-tokens?') && decodeURIComponent(C.CF_DNS_TOKEN_URL).includes('"key":"dns"') && decodeURIComponent(C.CF_DNS_TOKEN_URL).includes('"type":"edit"'));

  // DNS-only token cannot read zone settings → the SSL advisory DEGRADES to a note, never a throw
  const blind = async (url, init) => {
    const u = String(url);
    if (u.includes('/zones?name=')) return { json: async () => ({ result: [{ id: 'z1', account: { id: 'acc1' } }] }) };
    if (u.includes('/dns_records?name=')) return { json: async () => ({ result: [{ id: 'd1', type: 'A', proxied: true }] }) };
    if (u.includes('/settings/ssl')) return { json: async () => ({ success: false, errors: [{ message: 'insufficient scope' }] }) };
    return { json: async () => ({}) };
  };
  const apex = await C.cfApexSteps({ domain: DOMAIN, token: 'dns-only', fetchImpl: blind });
  check('apex_steps_degrade_without_settings_scope', apex.proxied && apex.warnings.some((w) => w.includes('not visible to this token')));
}

// ── 12. ceremony UX (rc.8) — the map/summary/gate are pinned so the STORY cannot silently regress
// back into an opaque sequence, and the tier promise the summary makes is PROVEN reachable.
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const bytes = JSON.stringify(g.genesis);

  // the road map: 5 steps, done/current/ahead marks move with progress
  check('map_has_five_steps', C.CEREMONY_STEPS.length === 5);
  const m2 = C.ceremonyMap(2);
  check('map_marks_progress', m2.includes('✅ 1/5') && m2.includes('▶️ 3/5') && m2.includes('⬜ 4/5'));

  // the live gate retries through propagation and narrates; exhaustion names the re-attest path
  let attempts = 0; const narrated = [];
  const flaky = async () => { attempts++; return attempts < 3 ? { text: async () => 'Payment required' } : { text: async () => bytes }; };
  const doc = await C.confirmLive({ domain: DOMAIN, genHash: g.genHash, fetchImpl: flaky, sleep: async () => {}, attempts: 5, delayMs: 1, onAttempt: (i, n, m) => narrated.push(i) });
  check('confirm_live_retries_through_propagation', attempts === 3 && narrated.length === 2 && !!doc);
  let exhausted = '';
  try { await C.confirmLive({ domain: DOMAIN, genHash: g.genHash, fetchImpl: async () => ({ text: async () => 'nope' }), sleep: async () => {}, attempts: 2, delayMs: 1 }); }
  catch (e) { exhausted = e.message; }
  // the re-attest hint must be RUNNABLE for everyone (npx form — a global `ust` is not assumed)
  check('confirm_live_exhaustion_names_reattest', exhausted.includes('npx @ust-protocol/cli discovery') && exhausted.includes('NOT granted'));

  // the closing summary: custody classes + tier ladder + NO operator-specific env name (the protocol
  // tool must not present one operator's convention as the standard)
  const s = C.ceremonySummary({ domain: DOMAIN, genHash: g.genHash, opKeyId: g.op.key_id, maxP: 256, outDir: '.', encrypted: true }).join('\n');
  check('summary_pins_custody', s.includes('COLD') && s.includes('WARM') && s.includes('DELETE') && s.includes('PUBLIC'));
  check('summary_shows_tier_ladder', s.includes('LIGHT') && s.includes('HIGH') && s.includes('TOP') && s.includes('--no-fork-confirmed'));
  check('summary_is_operator_neutral', !s.includes('UST_ENGINE_SK'));
  check('summary_no_overclaim', !/witnesses verified|anchored to bitcoin/i.test(s));

  // the promise is REAL: a document signed by the ceremony's op key resolves to VALID:HIGH with the
  // ceremony's own artifacts (genesis + keylog[0] + capacity grant from authority resolution)
  const t = (iso) => ({ generated_at: iso, valid_from: iso, valid_to: iso });
  const obs = await W.seal(P.buildState({ domain_shard: DOMAIN, ust_id: 'ust:20260712.14', key_id: g.op.key_id, class: 'observation' }, t('2026-07-12T14:00:00Z'), { probe: { kind: 'captured', value: { ok: 'true' } } }), g.op);
  const auth = P.resolveAuthority(obs, { genesis: g.genesis, keylog: [g.keylog0], noForkConfirmed: true });
  const high = P.verify(obs, { context: 'data', genesis: g.genesis, keylog: [g.keylog0], noForkConfirmed: true, capacity: auth.capacity });
  check('ceremony_artifacts_reach_high', high.result === 'VALID:HIGH' && high.publisher === DOMAIN);
}

// ── 13. the BY-HAND road (rc.9) — CF is a CHOICE, not the base: the manual guidance stays CONCRETE
// (a hands-on publisher gets real instructions, not "publish this file"), and the DoH confirm is shared.
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const dns = C.manualDnsGuide(DOMAIN, `ust-genesis=${g.genHash}`).join('\n');
  check('manual_dns_guide_is_concrete', dns.includes(`_ust.${DOMAIN}`) && dns.includes('TXT') && dns.includes('dig +short'));
  const srv = C.manualServingGuide(DOMAIN, '.').join('\n');
  check('manual_serving_guide_is_concrete', srv.includes('/.well-known/ust-genesis') && srv.includes('max-age=300') && srv.includes('cache key = path') && srv.includes('nginx') && srv.includes('GET'));
  // shared DoH confirm: sees the record when present, returns false (never throws) when absent
  const dohYes = async () => ({ json: async () => ({ Answer: [{ data: `"ust-genesis=${g.genHash}"` }] }) });
  const dohNo = async () => ({ json: async () => ({}) });
  check('doh_confirm_sees_record', await C.dohConfirmTxt({ domain: DOMAIN, genHash: g.genHash, fetchImpl: dohYes, sleep: async () => {}, attempts: 1 }) === true);
  check('doh_confirm_absent_is_false_not_throw', await C.dohConfirmTxt({ domain: DOMAIN, genHash: g.genHash, fetchImpl: dohNo, sleep: async () => {}, attempts: 2 }) === false);
  // the npm README carries the ceremony road + the tier ladder (the package page must explain itself)
  const readme = readFileSync(new URL('./README.md', import.meta.url), 'utf8');
  check('readme_shows_ceremony_road', readme.includes('1/5 🔑') && readme.includes('5/5 ⚓') && readme.includes('ust discovery'));
  check('readme_shows_tier_ladder', readme.includes('LIGHT') && readme.includes('VALID:HIGH') && readme.includes('--no-fork-confirmed'));
}

// ── 14. the closing story (owner: a flow must never STOP at a verdict) — what happened, the explicit
// PATH TO HIGH for the publisher's documents, and the housekeeping. Pinned so publish can't regress
// into ending on a bare verdict line again.
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const s = C.whatsNextSummary({ domain: DOMAIN, genHash: g.genHash }).join('\n');
  check('whats_next_names_the_high_path', s.includes('path to HIGH') && s.includes('operational-key.b64') && s.includes('ust-keylog-0') && s.includes('--no-fork-confirmed'));
  check('whats_next_names_housekeeping', s.includes('wrangler logout') && s.includes('cold storage') && s.includes('discovery ' + DOMAIN));
  check('whats_next_steps_are_marked', s.includes('✅ 1.') && s.includes('⬜ 2.') && s.includes('⬜ 4.'));
  check('whats_next_runnable_hints_are_npx', !/(^|\s)ust (verify|discovery)/m.test(s));
  check('whats_next_no_overclaim', !/witnesses verified|anchored to bitcoin/i.test(s));
}

// ── 15. the key log rides WITH the genesis (owner: a verifier needs BOTH — the adapter must not leave
// step-3-of-HIGH as homework), served APPEND-shaped (a rotation appends, never rewrites).
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const bytes = JSON.stringify(g.genesis);
  const klArr = JSON.stringify([g.keylog0]);
  const src = C.buildWorkerScript(bytes, klArr);
  check('worker_serves_keylog_route', src.includes('/.well-known/ust-keylog'));
  check('worker_without_keylog_backcompat', C.buildWorkerScript(bytes).includes('const KEYLOG = null'));
  const proj = C.buildWranglerProject({ domain: DOMAIN, genesisText: bytes, keylogText: klArr });
  check('wrangler_project_adds_keylog_route', proj['wrangler.toml'].includes('ust-keylog*'));
  const projNo = C.buildWranglerProject({ domain: DOMAIN, genesisText: bytes });
  check('wrangler_project_no_keylog_route_without', !projNo['wrangler.toml'].includes('ust-keylog*'));
  // the SERVED shape resolves: exactly what a consumer downloads from /.well-known/ust-keylog feeds
  // authority resolution and lifts an op-key document to VALID:HIGH
  const t = (iso) => ({ generated_at: iso, valid_from: iso, valid_to: iso });
  const obs = await W.seal(P.buildState({ domain_shard: DOMAIN, ust_id: 'ust:20260712.15', key_id: g.op.key_id, class: 'observation' }, t('2026-07-12T15:00:00Z'), { probe: { kind: 'captured', value: { ok: 'true' } } }), g.op);
  const served = JSON.parse(klArr);
  check('served_keylog_is_append_shaped', Array.isArray(served) && P.isValid(P.verify(served[0], { context: 'key' })));
  const auth = P.resolveAuthority(obs, { genesis: g.genesis, keylog: served, noForkConfirmed: true });
  const high = P.verify(obs, { context: 'data', genesis: g.genesis, keylog: served, noForkConfirmed: true, capacity: auth.capacity });
  check('served_keylog_resolves_to_high', high.result === 'VALID:HIGH');
}

// ── 16. the mirror method (owner: a general CLI method — and NEVER trust the user's word): mirrors are
// FETCHED and hash-matched against the canonical; the gh road delegates to the user's own CLI, idempotent.
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const other = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const bytes = JSON.stringify(g.genesis);
  const klArr = JSON.stringify([g.keylog0]);
  const mkNet = ({ mirrorBody, keylogMirrorBody, canonKeylog = klArr } = {}) => async (url) => {
    const u = String(url);
    if (u.includes(`/.well-known/ust-genesis`)) return { ok: true, text: async () => bytes };
    if (u.includes(`/.well-known/ust-keylog`)) return canonKeylog ? { ok: true, text: async () => canonKeylog } : { ok: false, status: 404, text: async () => '' };
    if (u.includes('mirror.example/g')) return mirrorBody ? { ok: true, text: async () => mirrorBody } : { ok: false, status: 404, text: async () => '' };
    if (u.includes('mirror.example/k')) return keylogMirrorBody ? { ok: true, text: async () => keylogMirrorBody } : { ok: false, status: 404, text: async () => '' };
    return { ok: false, status: 404, text: async () => '' };
  };

  // exact copies pass; a DIFFERENT genesis / a diverged key log FAIL — the fetch decides, never the claim
  const okM = await C.attestMirror({ domain: DOMAIN, genesisUrls: ['https://mirror.example/g'], keylogUrls: ['https://mirror.example/k'], fetchImpl: mkNet({ mirrorBody: bytes, keylogMirrorBody: klArr }) });
  check('mirror_exact_copies_pass', !okM.failed && okM.results.every((r) => r.status === 'pass'));
  const wrongG = await C.attestMirror({ domain: DOMAIN, genesisUrls: ['https://mirror.example/g'], fetchImpl: mkNet({ mirrorBody: JSON.stringify(other.genesis) }) });
  check('mirror_different_genesis_fails', wrongG.failed);
  const wrongK = await C.attestMirror({ domain: DOMAIN, genesisUrls: [], keylogUrls: ['https://mirror.example/k'], fetchImpl: mkNet({ keylogMirrorBody: JSON.stringify([other.keylog0]) }) });
  check('mirror_diverged_keylog_fails', wrongK.failed);
  const dead = await C.attestMirror({ domain: DOMAIN, genesisUrls: ['https://mirror.example/g'], fetchImpl: mkNet({}) });
  check('mirror_unreachable_fails_not_trusts', dead.failed); // a 404 mirror can NEVER pass on the user's word
  const noCanonKl = await C.attestMirror({ domain: DOMAIN, genesisUrls: [], keylogUrls: ['https://mirror.example/k'], fetchImpl: mkNet({ keylogMirrorBody: klArr, canonKeylog: null }) });
  check('mirror_keylog_skip_when_canonical_missing', noCanonKl.results[0].status === 'skip');

  // gh road: default branch resolved, create (no sha) vs update (sha) both idempotent, raw URLs returned
  const calls = [];
  const ghExec = async (args) => {
    calls.push(args.join(' '));
    if (args[1] === `repos/o/r` && args.includes('.default_branch')) return 'main\n';
    if (String(args[1]).includes('/contents/') && args[0] === 'api' && !args.includes('-X')) return args[1].includes('ust-genesis') ? 'abc123\n' : ''; // genesis exists → sha, keylog is new
    return '{}';
  };
  const pub = await C.ghMirrorPublish({ repo: 'o/r', genesisText: bytes, keylogText: klArr, execImpl: ghExec });
  check('gh_mirror_urls_are_raw', pub.genesisUrl === 'https://raw.githubusercontent.com/o/r/main/mirror/ust-genesis' && pub.keylogUrl.endsWith('/mirror/ust-keylog'));
  const putG = calls.find((c) => c.includes('-X PUT') && c.includes('ust-genesis'));
  const putK = calls.find((c) => c.includes('-X PUT') && c.includes('ust-keylog'));
  check('gh_mirror_update_carries_sha_create_does_not', putG.includes('sha=abc123') && !putK.includes('sha='));
}

// ── 17. external line-review of rc.15 — every reproduced finding frozen as a pin.
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const bytes = JSON.stringify(g.genesis);
  const klArr = JSON.stringify([g.keylog0]);

  // P0-1: a duplicate top-level member must be INVALID through the CLI path (it verified VALID before)
  const dupDoc = '{"ust":"1.0","ust":"1.0"' + bytes.slice(bytes.indexOf(',"state"'));
  const dupV = C.verifyRaw(dupDoc);
  check('p0_duplicate_member_rejected_via_cli_path', !P.isValid(dupV.verdict) && dupV.verdict.error === 'E-CANON');
  // cross-check: the CLI array-scanner agrees with the normative single-doc scanner — no silent drift
  check('p0_scanner_cross_checks_verifyJson', C.scanDupes(dupDoc) !== null && C.scanDupes(bytes) === null && !P.isValid(P.verifyJson(dupDoc)));
  // and a served duplicate-key genesis FAILS discovery outright
  const dupServe = await C.attestDiscovery({ domain: DOMAIN, fetchImpl: async (u) => (String(u).includes('ust-genesis') ? { ok: true, text: async () => dupDoc } : { ok: false, status: 404, text: async () => '' }) });
  check('p0_discovery_rejects_duplicate_member_serving', dupServe.verdict === 'FAILED');

  // P0-2: a valid NON-genesis / FOREIGN-domain document at the well-known must FAIL discovery
  const t = (iso) => ({ generated_at: iso, valid_from: iso, valid_to: iso });
  const obs = await W.seal(P.buildState({ domain_shard: DOMAIN, ust_id: 'ust:20260712.16', key_id: g.op.key_id, class: 'observation' }, t('2026-07-12T16:00:00Z'), { probe: { kind: 'captured', value: { ok: 'true' } } }), g.op);
  const serveDoc = (d) => async (u) => (String(u).includes('/.well-known/ust-genesis') ? { ok: true, text: async () => JSON.stringify(d) } : { ok: false, status: 404, text: async () => '' });
  const wrongClass = await C.attestDiscovery({ domain: DOMAIN, fetchImpl: serveDoc(obs) });
  check('p0_discovery_rejects_non_genesis', wrongClass.verdict === 'FAILED' && wrongClass.checks[0].detail.includes('not a genesis'));
  const foreign = await C.buildCeremony({ domain: 'other-name.invalid', profile: 'silver' });
  const wrongDomain = await C.attestDiscovery({ domain: DOMAIN, fetchImpl: serveDoc(foreign.genesis) });
  check('p0_discovery_rejects_foreign_domain', wrongDomain.verdict === 'FAILED' && wrongDomain.checks[0].detail.includes('not ' + DOMAIN));

  // P0-3: the API road publishes the key-log route too, and an unchained key log never reaches the network
  const apiCalls = [];
  const api = async (url, init) => {
    const u = String(url), m = init?.method || 'GET';
    apiCalls.push({ u, m });
    if (u.includes('/zones?name=')) return { json: async () => ({ result: [{ id: 'z1', account: { id: 'a1' } }] }) };
    if (u.includes('/workers/scripts/')) return { json: async () => ({ success: true }) };
    if (u.includes('/workers/routes') && m === 'GET') return { json: async () => ({ result: [] }) };
    if (u.includes('/workers/routes')) return { json: async () => ({ success: true }) };
    if (u.includes('/dns_records?name=')) return { json: async () => ({ result: [{ id: 'd1', type: 'A', proxied: true }] }) };
    if (u.includes('/settings/ssl')) return { json: async () => ({ result: { value: 'full' } }) };
    return { json: async () => ({}) };
  };
  await C.cfPublish({ domain: DOMAIN, genesisText: bytes, keylogText: klArr, token: 'x', fetchImpl: api });
  check('p0_api_road_publishes_keylog_route', apiCalls.filter((c) => c.u.endsWith('/workers/routes') && c.m === 'POST').length === 2);
  const foreignKl = JSON.stringify([foreign.keylog0]);
  const net2 = [];
  check('p0_unchained_keylog_never_deploys', await threw(() => C.cfPublish({ domain: DOMAIN, genesisText: bytes, keylogText: foreignKl, token: 'x', fetchImpl: async (u) => { net2.push(u); return { json: async () => ({}) }; } })) && net2.length === 0);
  check('keylog_chain_validator_bites', C.validateKeylogChain(g.genesis, [foreign.keylog0]) !== null && C.validateKeylogChain(g.genesis, [g.keylog0]) === null);

  // P1: remint probe is three-state and fail-closed
  const probe = (impl) => C.remintProbe({ domain: DOMAIN, fetchImpl: impl });
  check('remint_404_is_absent', (await probe(async () => ({ ok: false, status: 404, text: async () => '' }))).status === 'absent');
  check('remint_garbage_is_indeterminate', (await probe(async () => ({ ok: true, status: 200, text: async () => 'Payment required' }))).status === 'indeterminate');
  check('remint_foreign_genesis_is_indeterminate', (await probe(async () => ({ ok: true, status: 200, text: async () => JSON.stringify(foreign.genesis) }))).status === 'indeterminate');
  check('remint_network_error_is_indeterminate', (await probe(async () => { throw new Error('ETIMEDOUT'); })).status === 'indeterminate');
  check('remint_live_carries_hash', (await probe(async () => ({ ok: true, status: 200, text: async () => bytes }))).status === 'live');

  // P1: a matching TXT among CONFLICTING bindings must FAIL, not pass
  const conflictNet = async (u) => {
    const s2 = String(u);
    if (s2.includes('cloudflare-dns.com')) return { ok: true, json: async () => ({ Answer: [{ data: `"ust-genesis=${g.genHash}"` }, { data: '"ust-genesis=sha256:' + 'ff'.repeat(32) + '"' }] }) };
    if (s2.includes('/.well-known/ust-keylog')) return { ok: true, text: async () => klArr };
    if (s2.includes('/.well-known/ust-genesis')) return { ok: true, text: async () => bytes };
    return { ok: false, status: 404, text: async () => '' };
  };
  const conf = await C.attestDiscovery({ domain: DOMAIN, fetchImpl: conflictNet });
  check('conflicting_dns_bindings_fail', conf.checks.some((c) => c.id.startsWith('DNS record') && c.status === 'fail' && c.detail.includes('CONFLICTING')));

  // P1: custody + capacity + package exports (source/manifest pins)
  const src = readFileSync(new URL('./index.mjs', import.meta.url), 'utf8');
  check('key_files_are_0600_wx', src.includes('mode: 0o600, flag: \'wx\'') && src.includes('EEXIST'));
  check('passphrase_input_is_hidden', src.includes('askHidden') && src.includes('setRawMode'));
  const cap = await C.buildCeremony({ domain: DOMAIN, profile: 'silver', maxP: 256, maxBytes: 5000000 });
  const capObs = await W.seal(P.buildState({ domain_shard: DOMAIN, ust_id: 'ust:20260712.17', key_id: cap.op.key_id, class: 'observation' }, t('2026-07-12T17:00:00Z'), { probe: { kind: 'captured', value: { ok: 'true' } } }), cap.op);
  const grant = P.resolveAuthority(capObs, { genesis: cap.genesis, keylog: [cap.keylog0], noForkConfirmed: true });
  check('capacity_is_two_dimensional', cap.genesis.state.data.genesis.value.max_transcript_bytes === '5000000' && grant.capacity?.maxTranscriptBytes === 5000000);
  const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
  check('package_exports_the_core', pkg.exports === './index.mjs');
}

// ── 18. second external review (formal-model alignment) + the V8-reality pin.
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'silver' });
  const bytes = JSON.stringify(g.genesis);

  // TOP ≠ completeness (P0-doc): no CLI summary may claim completeness as a document-tier property
  const cs = C.ceremonySummary({ domain: DOMAIN, genHash: g.genHash, opKeyId: 'k', maxP: 64, outDir: '.', encrypted: true }).join('\n');
  check('top_never_claims_completeness', cs.includes('SEPARATE range verdict') && !/TOP[^\n]*provable completeness/.test(cs));
  const readme = readFileSync(new URL('./README.md', import.meta.url), 'utf8');
  check('readme_separates_completeness', readme.includes('never about a stream being complete') && !readme.includes('provably ordered and complete'));

  // transport admission on a Buffer happens BEFORE any utf8 decode (F.9 refusal, not a crash/verdict)
  const big = Buffer.from(bytes);
  const refused = C.verifyRaw(big, { maxInputBytes: 16 });
  check('buffer_admission_refuses_before_decode', refused.verdict.result === 'INDETERMINATE' && refused.verdict.reason === 'resource_limit' && refused.text === null);
  check('buffer_path_verifies_normally', P.isValid(C.verifyRaw(big).verdict));

  // V8 reality (Gemini): a depth bomb must yield a VERDICT, never a process crash — the parse is
  // try/catch-bounded and the duplicate scanner is ITERATIVE (array stack, no recursion)
  const bomb = '['.repeat(150000);
  const bombV = C.verifyRaw(bomb);
  check('depth_bomb_is_a_verdict_not_a_crash', bombV.verdict.result === 'INVALID');
  check('dup_scanner_is_iteration_safe', C.scanDupes(bomb) === null);
}

// ── 19. resolution is the DEFAULT path (owner: an agent/human sees LIGHT — or nothing — by default;
// over MCP that is a total failure). Source pins: bare `ust verify` auto-resolves the §20.1 pair from
// the document's own name; --offline forbids it; authority is NEVER silently granted (no-fork stays
// the human's explicit flag).
{
  const src = readFileSync(new URL('./index.mjs', import.meta.url), 'utf8');
  check('verify_auto_resolves_by_default', src.includes('resolving identity from https://') && src.includes("arg('offline', false)"));
  check('auto_resolution_never_grants_authority_silently', /noForkConfirmed: noFork/.test(src) && src.includes('no-fork unconfirmed') === false ? true : src.includes("noFork ? 'asserted by you") );
  check('offline_is_a_first_class_flag', src.includes('--offline'));
}

console.log(`\nPASS ${pass} FAIL ${fail} NOTES ${note}`);
if (fail) { console.error('\nFAILURES:\n  ' + fails.join('\n  ')); process.exit(1); }
console.log('✓ 9th-audit regression holds — the seven points cannot silently regress');
