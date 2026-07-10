// SPDX-License-Identifier: Apache-2.0
// Release evidence — the MECHANISM (P0-4 of the rc.6 follow-up audit), not a hand-made file.
//
//   node tools/release-evidence.mjs generate --based-on sha256:<hash>
//     Collects EVERY bound value itself (nothing hand-typed): git commit from the repo, npm tarball
//     integrity from the registry, the conformance-vectors hash from the file, the test report from a fresh
//     run. Builds a class:derivation UST (based_on = the audit lineage), signs it (ephemeral LIGHT key,
//     identity.mode=key), verifies it under BOTH independent verifiers, and writes
//     releases/<version>/{release-evidence.ust.txt, test-report.txt}.
//
//   node tools/release-evidence.mjs check
//     The gate. Reads the sealed evidence for the CURRENT version and re-derives reality against it:
//     the document verifies (both verifiers) · the vectors hash matches the file · the npm integrity matches
//     the registry · the bound commit exists in this repository · the committed test report matches its sealed
//     hash · a FRESH test run reproduces the sealed pass/fail counts. Any mismatch ⇒ exit 1.
//
// A release is not a claim; it is a verifiable chain — and this script is what makes that repeatable.
import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import * as P from '../packages/ust-protocol/index.mjs';
import * as W from '../packages/ust-web-signer/index.mjs';
import { verify as cleanRoom } from '../docs/ust-verify.mjs';

const root = new URL('..', import.meta.url).pathname;
const sh = (cmd) => execSync(cmd, { cwd: root, encoding: 'utf8' }).trim();
const sha256 = (bufOrStr) => createHash('sha256').update(bufOrStr).digest('hex');
const VER = P.VERSION.spec;
const dir = `${root}releases/${VER}`;
const evidencePath = `${dir}/release-evidence.ust.txt`;
const reportPath = `${dir}/test-report.txt`;

const collect = () => {
  const npm = JSON.parse(sh(`npm view ust-protocol@${VER} dist --json`));
  // the bound commit is the one the npm ARTIFACT was published from (registry gitHead) — not wherever this
  // script happens to run: evidence binds the artifact's source, and that commit survives squash-merges.
  let commit = '';
  try { commit = sh(`npm view ust-protocol@${VER} gitHead`); } catch { /* registry omitted gitHead */ }
  if (!/^[0-9a-f]{40}$/.test(commit)) { commit = sh('git rev-parse HEAD'); console.warn('! registry has no gitHead — bound the local HEAD instead'); }
  return { commit, npm, vectorsSha: sha256(readFileSync(`${root}vectors/conformance-vectors.json`)) };
};

function runTests() {
  const out = execSync('npm test', { cwd: root, encoding: 'utf8' });
  const m = out.match(/PASS (\d+)\s+FAIL (\d+)\s+NOTES (\d+)/);
  if (!m || m[2] !== '0') { console.error(out); throw new Error('test suite not green — no evidence for a red release'); }
  return { out, counts: `PASS ${m[1]} FAIL ${m[2]} NOTES ${m[3]}` };
}

function decodeBlob(blob) {
  const marker = '———UST(base64)———';
  const b64 = blob.includes(marker) ? blob.slice(blob.lastIndexOf(marker) + marker.length).trim() : blob.trim();
  return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
}

const mode = process.argv[2];

if (mode === 'generate') {
  const basedOn = (process.argv.indexOf('--based-on') > -1) ? process.argv[process.argv.indexOf('--based-on') + 1] : null;
  if (!/^sha256:[0-9a-f]{64}$/.test(basedOn || '')) { console.error('need --based-on sha256:<content_hash of the audit lineage head>'); process.exit(1); }
  // release HISTORY lives in the chain: --prev links the PREVIOUS release evidence (tree holds only the head)
  const prev = (process.argv.indexOf('--prev') > -1) ? process.argv[process.argv.indexOf('--prev') + 1] : null;
  if (prev && !/^sha256:[0-9a-f]{64}$/.test(prev)) { console.error('--prev must be sha256:<content_hash>'); process.exit(1); }
  const { commit, npm, vectorsSha } = collect();
  const t = runTests();
  mkdirSync(dir, { recursive: true });
  writeFileSync(reportPath, t.out);
  const signer = await W.generateSigner();
  const { ust_id, time } = W.nowFrame();
  const state = P.buildDerivation({ domain_shard: signer.key_id, ust_id, key_id: signer.key_id }, time, {
    release_evidence: { kind: 'computed', value: {
      release: `ust-protocol ${VER} (spec + reference implementation)`,
      what_this_binds: 'the source commit, the published npm artifact, the conformance contract and the machine test report — one signed object; based_on carries the audit lineage (P0-4). Generated and checked by tools/release-evidence.mjs — regenerate, never hand-edit.',
      git_commit: commit,
      git_repository: 'https://github.com/thelabmd/UST-Protocol',
      npm_package: `ust-protocol@${VER}`,
      npm_dist_integrity: npm.integrity,
      npm_dist_shasum: npm.shasum,
      conformance_vectors_sha256: vectorsSha,
      test_report_sha256: sha256(t.out),
      test_result: `${t.counts} (conformance runner; asserts spec == package == vectors version)`,
      ...(prev ? { previous_release_evidence: prev } : {}),
    } },
  }, [{ hash: basedOn }, ...(prev ? [{ hash: prev }] : [])]);
  const doc = await W.seal(state, signer);
  const r1 = P.verify(doc, { context: 'data' });
  const r2 = await cleanRoom(doc, { context: 'data' });
  if (!P.isValid(r1) || !P.isValid(r2)) throw new Error('evidence does not verify: ' + (r1.error || r2.error));
  const blob = 'UST/1.0; ref=pkg:npm/ust-protocol; web=https://thelabmd.github.io/UST-Protocol/; call=verify(doc,{context:"data"}); hash=domain-separated; trust=resolve-by-name; proves=bytes+key+time\n———UST(base64)———\n'
    + Buffer.from(JSON.stringify(doc), 'utf8').toString('base64');
  writeFileSync(evidencePath, blob);
  console.log(`✓ ${VER}: evidence generated, ${r1.result} under both verifiers, content_hash ${r1.content_hash}`);
} else if (mode === 'check') {
  if (!existsSync(evidencePath)) { console.error(`✗ no evidence for the current version ${VER} (${evidencePath}) — run generate`); process.exit(1); }
  const doc = decodeBlob(readFileSync(evidencePath, 'utf8'));
  const v = doc.state.data.release_evidence.value;
  const { npm, vectorsSha } = collect();
  const fresh = runTests();
  const checks = [
    ['document verifies (reference)', P.isValid(P.verify(doc, { context: 'data' }))],
    ['document verifies (clean-room)', P.isValid(await cleanRoom(doc, { context: 'data' }))],
    ['version bound == current VERSION', v.npm_package === `ust-protocol@${VER}`],
    ['vectors hash matches the file', v.conformance_vectors_sha256 === vectorsSha],
    ['npm integrity matches the registry', v.npm_dist_integrity === npm.integrity && v.npm_dist_shasum === npm.shasum],
    ['bound commit exists in this repo', (() => { try { sh(`git cat-file -e ${v.git_commit}`); return true; } catch { return false; } })()],
    ['committed test report matches its sealed hash', sha256(readFileSync(reportPath, 'utf8')) === v.test_report_sha256],
    ['fresh test run reproduces the sealed counts', v.test_result.startsWith(fresh.counts)],
  ];
  let bad = 0;
  for (const [name, ok] of checks) { console.log((ok ? '  ✓ ' : '  ✗ ') + name); if (!ok) bad++; }
  console.log(bad ? `✗ evidence check FAILED (${bad})` : `✓ release evidence for ${VER} holds — the release is a verifiable chain`);
  process.exit(bad ? 1 : 0);
} else {
  console.error('usage: node tools/release-evidence.mjs generate --based-on sha256:<hash> | check');
  process.exit(1);
}
