// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:no — runs the committed byte vectors through the reference checker
// LANGUAGE-NEUTRAL runner: decode each byte-vector (base64url → bytes), run checkAuthorityProofBytes, assert result +
// (for a negative) that the reason carries the expected code. No object builders — this is exactly what a Rust/Go/WASM/
// Lean-extracted checker would run. Also enforces the security-condition coverage manifest (every side-condition has a
// present negative vector — owner completion criterion 8) and the config_id extensionality differential (P1-02).
import { checkAuthorityProofBytes } from './reference-checker.mjs';
import { readFileSync } from 'node:fs';

const suite = JSON.parse(readFileSync(new URL('../../vectors/checker-byte-vectors.json', import.meta.url)));
const manifest = JSON.parse(readFileSync(new URL('../../vectors/checker-security-manifest.json', import.meta.url)));
const dec = (b64) => new Uint8Array(Buffer.from(b64, 'base64url'));
let pass = 0, fail = 0; const fails = [];
const results = {};

for (const v of suite.vectors) {
  const r = checkAuthorityProofBytes(dec(v.package_b64url), dec(v.config_b64url));
  results[v.id] = r;
  let ok = r.result === v.expected.result;
  if (ok && v.expected.code) ok = typeof r.reason === 'string' && r.reason.includes(v.expected.code);
  if (ok && v.expected.judgment_kind) ok = !!r.judgment && r.judgment.kind === v.expected.judgment_kind;
  if (ok) pass++; else { fail++; fails.push(v.id + ' → ' + JSON.stringify({ result: r.result, reason: r.reason, kind: r.judgment && r.judgment.kind }).slice(0, 160)); }
}
// config_id extensionality differential (P1-02): a swapped-pub config must yield a DIFFERENT config_id.
for (const v of suite.vectors) if (v.expected.config_id_differs_from) {
  const a = results[v.id], b = results[v.expected.config_id_differs_from];
  if (a && b && a.config_id && b.config_id && a.config_id !== b.config_id) pass++;
  else { fail++; fails.push(v.id + ': config_id must differ from ' + v.expected.config_id_differs_from); }
}
// coverage manifest: every listed negative vector must exist AND be a non-VALID outcome.
const byId = new Map(suite.vectors.map((v) => [v.id, v]));
for (const c of manifest.security_conditions) for (const nv of c.negative_vectors) {
  const v = byId.get(nv);
  if (!v) { fail++; fails.push('manifest ' + c.id + ' → missing vector ' + nv); }
  else if (v.expected.result === 'VALID') { fail++; fails.push('manifest ' + c.id + ' → ' + nv + ' is not a negative vector'); }
  else pass++;
}

console.log('\n  checker byte-vectors + coverage manifest (' + suite.reference_checker + ')   PASS ' + pass + '   FAIL ' + fail);
if (fails.length) { fails.slice(0, 12).forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ language-neutral byte corpus holds; every security condition has a present negative vector (criterion 8)');
