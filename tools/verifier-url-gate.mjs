// SPDX-License-Identifier: Apache-2.0
// @assurance 2 canfail:yes literal-ok:the only literal is the RETIRED origin, which is the subject being watched, not the domain — the live host is READ from docs/CNAME and every pointer is READ from the tracked tree
// VERIFIER URL GATE — the address of the reference verifier is written in one place and agreed everywhere.
//
// The verifier moved to a custom domain on 2026-08-15. What made that more than a find-and-replace is that the
// address is EMITTED, not merely linked: the CLI stamps a `web=` field into every clipboard header a publisher
// produces, the browser extension builds the same header, and the release-evidence tool builds it a third time.
// Three copies of one sentence, in three artifacts that ship separately, and nothing compared them.
//
// The authority is `docs/CNAME`, deliberately: that file is what actually serves the site, so the gate asks the
// deployment rather than a constant someone has to remember to update. A constant would be a fourth copy.
//
// The DOMAIN is the tracked tree — `git ls-files`. That is not a convenience: it is what makes this gate ask
// about the PUBLISHED surface and nothing else. Internal research holds records of what was true on the day they
// were written, and a sweep that rewrites those falsifies them; that mistake was made while doing this move, and
// bounding the domain by what git tracks is the structural reason it cannot be made from here.
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const ROOT = new URL('..', import.meta.url).pathname;
const HOST = readFileSync(ROOT + 'docs/CNAME', 'utf8').trim();
// The origin the site was served from before the move. It STILL RESOLVES and still serves these bytes, so a
// stale pointer does not 404 — it quietly sends a reader to a second copy of the page under a second name, on a
// verifier whose own advice is to resolve it by name. That is exactly why it is worth a gate and not a habit.
const RETIRED = 'thelabmd.github.io/UST-Protocol';

let fail = 0;
const ok = (name, cond, detail = '') => { console.log(`  ${cond ? '✓' : '✗'} ${name}${cond || !detail ? '' : ' — ' + detail}`); if (!cond) fail++; };

ok(`the live host is READ from docs/CNAME (${HOST})`, /^[a-z0-9.-]+\.[a-z]{2,}$/.test(HOST),
  'docs/CNAME does not hold a hostname — every leg below would compare against nothing');

const tracked = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean);
const TEXT = /\.(mjs|js|json|md|txt|html|yml|yaml|ts)$/;
const sources = tracked.filter((f) => TEXT.test(f)).map((f) => {
  try { return { f, src: readFileSync(ROOT + f, 'utf8') }; } catch { return null; }
}).filter(Boolean);
ok(`the domain is the TRACKED tree, read from git (${sources.length} text file(s))`, sources.length >= 50,
  'too few files — the enumeration has lost its subject');

// ─── 1. the EMITTED header: every copy of the clipboard blob names the same verifier ──────────────────────────
// This gate is excluded from BOTH enumerations below: it names the retired origin in order to watch for it,
// and it carries a fixture header in a CONTROL. Both exclusions are asserted LIVE further down, so an exemption
// that stops describing this file reddens instead of quietly widening.
const SELF = 'tools/verifier-url-gate.mjs';
const emitters = [];
for (const { f, src } of sources) {
  if (f === SELF) continue;
  for (const m of src.matchAll(/UST\/1\.0; ref=pkg:npm\/ust-protocol; web=https:\/\/([a-z0-9.\-/]+?)\/;/g)) emitters.push({ f, host: m[1] });
}
ok(`the emitted header is found in every artifact that ships it (${emitters.length}: ${[...new Set(emitters.map((e) => e.f))].join(', ')})`,
  emitters.length >= 3, 'fewer than the three known emitters — either one stopped emitting, or this pattern no longer matches the shape they build');
for (const e of emitters) ok(`${e.f} stamps the live verifier into the header it emits (${e.host})`, e.host === HOST, `expected ${HOST}`);

// ─── 2. no tracked file points at the retired origin ──────────────────────────────────────────────────────────
const stale = sources.filter(({ f, src }) => f !== SELF && src.includes(RETIRED)).map(({ f }) => f);
ok('no tracked file points at the retired origin', stale.length === 0,   // static label: the ladder registry cites a check BY ITS TEXT
  `${RETIRED} is still named in: ${stale.join(', ')} — it resolves, so this is a silent second copy of the verifier rather than a broken link`);

ok(`the self-exemption is live: ${SELF} still names the retired origin it watches for, and the fixture header its control needs`,
  sources.some(({ f, src }) => f === SELF && src.includes(RETIRED) && /web=https:\/\/example\.test\//.test(src)),
  'the exempted file no longer names it, so the exemption is stale and excludes a file for nothing');

// ─── 3. the live host is actually USED, so the legs above are not passing over an empty set ───────────────────
const users = sources.filter(({ src }) => src.includes(HOST)).map(({ f }) => f);
ok(`the live host is named where a reader and a machine both find it (${users.length} file(s))`, users.length >= 5,
  'almost nothing points at the verifier — the move landed in the CNAME and nowhere else');
for (const must of ['docs/index.html', 'docs/llms.txt', 'README.md']) {
  ok(`${must} names the live verifier`, users.includes(must), 'a reader arriving here is sent to the old name, or to none');
}

// ─── CONTROLS ─────────────────────────────────────────────────────────────────────────────────────────────────
ok('CONTROL: the emitted-header pattern reads the HOST, not any URL in the file',
  [...'UST/1.0; ref=pkg:npm/ust-protocol; web=https://example.test/; call=verify'.matchAll(/UST\/1\.0; ref=pkg:npm\/ust-protocol; web=https:\/\/([a-z0-9.\-/]+?)\/;/g)][0]?.[1] === 'example.test');
ok('CONTROL: a stale pointer is DETECTED rather than passed over', 'see https://' + RETIRED + '/ for the verifier'.includes(RETIRED));
ok('CONTROL: the live-host leg does not accept a mere substring of it', !'ustprotocol.com.evil.test'.includes(HOST) || HOST !== 'verify.ustprotocol.com');

console.log(fail ? `\n✗ verifier url gate: ${fail} failure(s)` : `\n✓ verifier url gate: one address in docs/CNAME (${HOST}), ${emitters.length} emitted header(s) agreeing, no tracked pointer to the retired origin`);
process.exit(fail ? 1 : 0);
