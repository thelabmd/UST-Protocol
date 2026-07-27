// SPDX-License-Identifier: Apache-2.0
// Discovery SERVING gate — the relation nothing checked until 2026-07-27: an artifact a command PRODUCES must have a
// path that SERVES it, and that path must exist on EVERY road to production.
//
// The defect it exists for: `ust cadence` shipped (3d58537) writing `./ust-cadence`, while the CF adapter's worker, its
// routes, and the §20.1 attestation had never heard of the word. The operator was handed a signed file and nowhere to
// put it. All 40 gates stayed green throughout — every one of them asks "does this capability exist on both surfaces",
// and none asks "can the result be SERVED". Two things shipped in the same session, and the seam between them was
// checked by nothing. The owner found it by asking a question; no gate could have.
//
// So this gate pins the RELATION rather than any instance of it:
//   produced ⊆ served   ·   served ⇒ dispatched   ·   dispatched ⇒ routed (on BOTH roads)   ·   served ⇒ attested
// A fifth discovery artifact fails here until it is wired end to end, and the exclusions below carry their reasons in
// the file rather than in someone's memory. (rev92)
import { readFileSync } from 'node:fs';
import { DISCOVERY_ARTIFACTS, buildWorkerScript, buildWranglerProject, cfPublish, attestDiscovery, buildCeremony } from '../packages/ust-cli/index.mjs';

const SRC = readFileSync(new URL('../packages/ust-cli/index.mjs', import.meta.url), 'utf8');
const fail = [];
let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// ── 1. produced ⊆ served. The PRODUCED set is read out of the source, not listed here: a new
// `writeFileSync(`${outDir}/ust-<name>`)` enters this set by existing, and fails the gate until it is either wired
// into DISCOVERY_ARTIFACTS or excluded below WITH a reason. That is the difference between enumerating a domain and
// naming one member of it.
// (the write goes through three helpers — writeFileSync directly, and writePublic/writeSecret which add the 'wx'
// no-clobber custody policy — so the probe must know all three, or it silently measures a third of the truth)
const produced = [...SRC.matchAll(/(?:writeFileSync|writePublic|writeSecret)\(`\$\{outDir\}\/ust-([a-z]+)(?:-\d+)?`/g)].map((m) => m[1]);
check(produced.length >= 3, `the PRODUCED probe found only ${produced.length} artifacts — it has gone vacuous and would pass no matter what`);
for (const p of new Set(produced)) {
  check(DISCOVERY_ARTIFACTS.includes(p), `the CLI writes ust-${p} but it is not in DISCOVERY_ARTIFACTS — an artifact with nowhere to be served (this is exactly the cadence defect)`);
}

// ── 2. served ⇒ dispatched, checked BEHAVIOURALLY by running the generated worker rather than grepping it. A grep is
// what lied during the investigation: it counted `ust cadence`'s FETCH of the well-known as a SERVE.
const texts = Object.fromEntries(DISCOVERY_ARTIFACTS.map((a, i) => [a, JSON.stringify({ probe: a, i })]));
const src = buildWorkerScript(texts.genesis, texts.keylog, texts.witness, texts.cadence);
const worker = (await import('data:text/javascript,' + encodeURIComponent(src))).default;
for (const a of DISCOVERY_ARTIFACTS) {
  const r = await worker.fetch(new Request(`https://x.example/.well-known/ust-${a}`));
  check(r.status === 200 && (await r.text()) === texts[a], `the generated worker does not serve /.well-known/ust-${a} with its exact bytes (HTTP ${r.status})`);
}
// and an artifact this deploy does NOT carry must 404 — the ABSENT/UNREADABLE distinction `ust cadence` reads to tell
// "this is the first declaration" from "do not chain onto a head you cannot see" depends on precisely this.
const bare = (await import('data:text/javascript,' + encodeURIComponent(buildWorkerScript(texts.genesis)))).default;
for (const a of DISCOVERY_ARTIFACTS.filter((x) => x !== 'genesis')) {
  const r = await bare.fetch(new Request(`https://x.example/.well-known/ust-${a}`));
  check(r.status === 404, `a deploy carrying only a genesis answered /.well-known/ust-${a} with HTTP ${r.status} instead of 404 — absent must be indistinguishable from never-declared`);
}

// ── 3. dispatched ⇒ routed, on BOTH roads. The wrangler road and the API road creating DIFFERENT route sets is a
// defect this repo has already had (line-review P0-3, the key-log): the worker answered a path Cloudflare never
// routed to it, so the bytes existed and the URL 404'd.
const toml = buildWranglerProject({ domain: 'x.example', genesisText: texts.genesis, keylogText: texts.keylog, witnessText: texts.witness, cadenceText: texts.cadence })['wrangler.toml'];
for (const a of DISCOVERY_ARTIFACTS) {
  check(toml.includes(`/.well-known/ust-${a}*`), `wrangler.toml carries no route for ust-${a} — the worker would answer a path CF never routes to it`);
}

// cfPublish is fail-closed: it refuses to touch the network before the genesis VERIFIES, so this leg needs a REAL
// ceremony rather than a placeholder string. (My first draft passed a placeholder, cfPublish correctly threw, the
// catch swallowed it, and the gate reported four product defects that were entirely my own harness.)
const DOM = 'x.example';
const cer = await buildCeremony({ domain: DOM, profile: 'silver' });
const realGenesis = JSON.stringify(cer.genesis);
const realKeylog = JSON.stringify([cer.keylog0]);

const routed = [];
const fakeCf = async (u, init) => {
  const s = String(u);
  if (s.includes('/zones?name=')) return { json: async () => ({ result: [{ id: 'z1', account: { id: 'a1' } }] }) };
  if (s.endsWith('/workers/routes') && init?.method === 'POST') { routed.push(JSON.parse(init.body).pattern); return { json: async () => ({ success: true }) }; }
  if (s.endsWith('/workers/routes')) return { json: async () => ({ result: [] }) };
  if (s.includes('/dns_records')) return { json: async () => ({ success: true, result: [] }) };   // a LIST endpoint — the apex step filters it
  return { json: async () => ({ success: true, result: {} }) };
};
let cfErr = null;
await cfPublish({ domain: DOM, genesisText: realGenesis, keylogText: realKeylog, witnessText: texts.witness, cadenceText: texts.cadence, token: 'x', fetchImpl: fakeCf })
  .catch((e) => { cfErr = e.message; });
check(cfErr === null, `cfPublish threw before routing — the leg would be vacuous: ${cfErr}`);
for (const a of DISCOVERY_ARTIFACTS) {
  check(routed.includes(`${DOM}/.well-known/ust-${a}*`), `the API road (cfPublish) never created the route for ust-${a} — the two roads to production disagree, which is line-review P0-3 again`);
}
check(routed.length === DISCOVERY_ARTIFACTS.length, `the API road created ${routed.length} routes for ${DISCOVERY_ARTIFACTS.length} artifacts — ${JSON.stringify(routed)}`);

// ── 4. served ⇒ attested. What is served but never attested is a property no operator can confirm.
// EXCLUSION, with its reason in the file rather than in a habit: `witness` (#68) is served by the adapter but has no
// §20.1 probe. That is a real hole, not a decision — filed as #91, and listed here so the boundary is VISIBLE.
// When the probe lands, delete this line and the gate tightens by itself.
const ATTEST_EXEMPT = { witness: 'no §20.1 probe yet — tracked in #91; served by the adapter but unattestable today' };
// attestDiscovery returns early when (1) fails — "nothing downstream is meaningful without it" — so the harness must
// actually serve a verifying genesis, or every later probe is unreached and the leg measures the early return.
const probeIds = [];
const attested = await attestDiscovery({
  domain: DOM,
  fetchImpl: async (u) => {
    const s = String(u); probeIds.push(s);
    if (s.includes('cloudflare-dns.com')) return { ok: true, json: async () => ({}) };
    if (s.includes('/.well-known/ust-genesis')) return { ok: true, text: async () => realGenesis };
    if (s.includes('/.well-known/ust-keylog')) return { ok: true, text: async () => realKeylog };
    return { ok: false, status: 404, text: async () => '' };
  },
});
check(attested.hash !== null, 'the attestation harness never got past probe (1) — every later leg would be measuring an early return, not a serving path');
for (const a of DISCOVERY_ARTIFACTS) {
  if (ATTEST_EXEMPT[a]) continue;
  check(probeIds.some((p) => p.includes(`/.well-known/ust-${a}`)), `attestDiscovery never probes /.well-known/ust-${a} — the operator cannot be told whether it is served`);
}

// ── 5. the pin itself must be able to FAIL. A gate that cannot go red is a statement about nothing; every legged
// check above is asserted against a member the code has never heard of.
const GHOST = 'phantom';
check(!DISCOVERY_ARTIFACTS.includes(GHOST), 'the mutation probe collides with a real artifact');
const ghostWorker = (await import('data:text/javascript,' + encodeURIComponent(buildWorkerScript(texts.genesis)))).default;
check((await ghostWorker.fetch(new Request(`https://x.example/.well-known/ust-${GHOST}`))).status === 404, 'the dispatch mutation probe does not discriminate — leg 2 would pass for an artifact that does not exist');
check(!toml.includes(`/.well-known/ust-${GHOST}*`), 'the route mutation probe does not discriminate — leg 3 would pass for an artifact that does not exist');
check(!produced.includes(GHOST), 'the produced-set mutation probe does not discriminate — leg 1 would pass for an artifact nothing writes');

console.log(`\n  discovery serving   PASS ${pass}   FAIL ${fail.length}   (${DISCOVERY_ARTIFACTS.length} artifacts × produced/dispatched/routed×2/attested)`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every artifact the CLI produces has a serving path on both roads, and an absent one is indistinguishable from never-declared');
console.log('    exclusions carried in-file: ' + Object.entries(ATTEST_EXEMPT).map(([k, v]) => `${k} (${v})`).join(' · '));
