// SPDX-License-Identifier: Apache-2.0
// spec↔code drift gate (UST-oy8) — LAYER 1: RENDER the spec's canonical string-set regions FROM the code REGISTRY
// (index.mjs), so spec prose cannot silently disagree with the implementation. Each region is delimited by
// `<!-- BEGIN spec-sync:NAME -->` / `<!-- END spec-sync:NAME -->` in spec/UST-1.0.md; this rewrites the content
// between them. The gate is `node gen-spec-registry.mjs && git diff --exit-code spec/UST-1.0.md` (same immutability
// pattern as test:vectors): if REGISTRY moved and the spec was not regenerated + committed, CI fails.
import { readFileSync, writeFileSync } from 'node:fs';
import { REGISTRY } from '../packages/ust-protocol/index.mjs';

const tick = (a) => a.map((x) => '`' + x + '`');
const blocks = {
  'error-codes': tick(REGISTRY.errorCodes).join(', '),
  'purposes': tick(REGISTRY.purposes).join(' | '),
  'evidence-order': tick(REGISTRY.evidenceOrder).join(' | '),
  'verified-evidence-fields': 'required ' + tick(REGISTRY.verifiedEvidenceFields.required).join(', ')
    + '; optional ' + tick(REGISTRY.verifiedEvidenceFields.optional).join(', '),
};

const path = new URL('../spec/UST-1.0.md', import.meta.url);
let spec = readFileSync(path, 'utf8');
let n = 0;
for (const [name, content] of Object.entries(blocks)) {
  const re = new RegExp('(<!-- BEGIN spec-sync:' + name + ' -->)[\\s\\S]*?(<!-- END spec-sync:' + name + ' -->)');
  if (!re.test(spec)) { console.error('  ✗ spec is missing the region <!-- BEGIN/END spec-sync:' + name + ' -->'); process.exit(1); }
  spec = spec.replace(re, '$1\n' + content + '\n$2');
  n++;
}
writeFileSync(path, spec);
console.log('  generated ' + n + ' spec-sync regions in spec/UST-1.0.md from index.mjs REGISTRY');
