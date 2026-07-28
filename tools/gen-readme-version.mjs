// SPDX-License-Identifier: Apache-2.0
// Version sync gate — the README Status line AND the private monorepo-root package.json version both track the CANONICAL
// `VERSION.spec` (packages/ust-protocol/index.mjs), the ONE version source (rc.6 "one version source"). Counterpart to
// gen-spec-registry.mjs for the spec: run it, then `git diff --exit-code README.md package.json`, so neither can silently
// drift behind the spec/package version again (README had — rc.17; root package.json had — rc.34, while spec/package were
// rc.36). Idempotent. Per-WORKSPACE package versions (cli/mcp/…) version independently and are NOT touched here; the wire
// version `ust: "1.0"` is a different axis (stable across rc's) and is untouched.
import { readFileSync, writeFileSync } from 'node:fs';
import { VERSION } from '../packages/ust-protocol/index.mjs';

// 1) README status — the Status prose moved into the TUI SVG panel (gen-status-svg.mjs, .github/status.svg); the markdown
// carries it as the image ALT text (searchable + screen-reader text). Replace only the version token in that alt's backticks.
const readmePath = new URL('../README.md', import.meta.url);
let readme = readFileSync(readmePath, 'utf8');
// TWO version tokens track VERSION.spec: the status image ALT (searchable text agents read) AND the plain-text Status
// blockquote below it (the fallback for readers/agents that don't render the image). Both are stamped + git-diff-gated.
const anchors = [
  // Form-agnostic on purpose: an illustration's alt lives in markdown `![…]` when the panel is one artifact, and in
  // `<img alt="…">` when it has a light variant behind <picture>. This stamps the version token either way, so a
  // panel moving between the two forms cannot silently strand the version. See tools/lib/readme-image.mjs.
  { re: /((?:!\[|alt=")UST status:\s*`)[^`]+(`)/, what: 'status image alt' },
  { re: /(\*\*Status:\s*`)[^`]+(`\*\*)/, what: 'status text blockquote' },
];
for (const { re, what } of anchors) {
  if (!re.test(readme)) { console.error(`  ✗ README ${what} anchor not found — update tools/gen-readme-version.mjs if the README format changed`); process.exit(1); }
  const before = (readme.match(re) || [])[0];
  readme = readme.replace(re, `$1${VERSION.spec}$2`);
  console.log(`  ✓ README ${what} → ${VERSION.spec}` + (before.includes(VERSION.spec) ? '  [already in sync]' : `  [was: ${before.replace(/[^0-9a-z.\-]/gi, '').replace(/^UST.*?status|Status/i, '')}]`));
}
writeFileSync(readmePath, readme);

// 2) root package.json version — the FIRST `"version": "..."` in the file is the root package's own (deps never use that
// key). Replace only that token, so JSON formatting is byte-preserved (no reformat, minimal diff).
const pkgPath = new URL('../package.json', import.meta.url);
const pkg = readFileSync(pkgPath, 'utf8');
const rePkg = /("version":\s*")[^"]+(")/;
if (!rePkg.test(pkg)) {
  console.error('  ✗ root package.json has no "version" field');
  process.exit(1);
}
const pkgBefore = (pkg.match(rePkg) || [])[0];
writeFileSync(pkgPath, pkg.replace(rePkg, `$1${VERSION.spec}$2`));
console.log(`  ✓ root package.json version → ${VERSION.spec}` + (pkgBefore.includes(VERSION.spec) ? '  [already in sync]' : `  [was: ${pkgBefore.replace(/"version":\s*"|"/g, '')}]`));
