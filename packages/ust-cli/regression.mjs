// SPDX-License-Identifier: Apache-2.0
// CLI ceremony regression — the 9th audit's seven points, frozen as tests so a TENTH audit can't silently
// reintroduce the ninth defect. Each check name IS the guarantee it locks. Runs the exported ceremony core
// (no live network: CF fetch + DoH readback are injected). Prints `PASS n FAIL n NOTES n` like conformance.
import { readFileSync } from 'node:fs';
import * as C from './index.mjs';
import * as P from 'ust-protocol';

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

// ── 1. gold_without_signer_warns — a software gold root must announce its ASSURANCE LIMIT
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'gold' });
  check('gold_without_signer_warns', g.warnings.some((w) => w.includes('ASSURANCE LIMIT')));
  const s = await C.buildCeremony({ domain: DOMAIN, profile: 'gold', signerRef: 'pkcs11:slot0' });
  check('gold_with_signer_clears_warning', s.warnings.length === 0);
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
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'gold' });
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
}

// ── 7. witness_stage_does_not_claim_execution — the summary PREPARES the stage, never claims it ran
{
  const g = await C.buildCeremony({ domain: DOMAIN, profile: 'gold' });
  const lines = C.stageSummary({ genHash: g.genHash, witnesses: [], profile: 'gold' }).join(' ');
  const prepared = lines.includes('STAGE PREPARED (not executed');
  const falseClaim = /verified \d+ witnesses|witnesses verified|✓[^\n]*anchored|anchored to bitcoin/i.test(lines);
  check('witness_stage_does_not_claim_execution', prepared && !falseClaim);
  // belt + suspenders: no affirmative-success overclaim shape may creep into the CLI source itself
  const src = readFileSync(new URL('./index.mjs', import.meta.url), 'utf8');
  const forbidden = [/verified \d+ witnesses/i, /byte-for-byte match/i, /✓[^\n]*anchored to bitcoin/i, /queue anchor[^\n]*✓/i];
  const hit = forbidden.filter((re) => re.test(src)).map((re) => re.source);
  check('source_has_no_affirmative_overclaim', hit.length === 0, hit.join(' | '));
}

console.log(`\nPASS ${pass} FAIL ${fail} NOTES ${note}`);
if (fail) { console.error('\nFAILURES:\n  ' + fails.join('\n  ')); process.exit(1); }
console.log('✓ 9th-audit regression holds — the seven points cannot silently regress');
