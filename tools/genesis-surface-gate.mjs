// SPDX-License-Identifier: Apache-2.0
// Genesis SURFACE gate — every field `buildGenesis` can place in a genesis must be reachable from the tool that
// performs the ceremony, or excluded here with a reason.
//
// MEASURED, 2026-07-28. `buildGenesis` accepts seven value fields. The CLI never called it: it hand-built the value
// from five, and had done so long enough that `checkpoint_authority` and `recovery` existed in the protocol and were
// unreachable from the only tool that performs a ceremony. The live reference operator's genesis carries three
// fields — `pub`, `role`, `max_partitions` — so both are absent there.
//
// WHY THAT IS WORSE THAN AN ORDINARY GAP. Those two fields can be set at ceremony time ONLY. Changing either means a
// NEW genesis, i.e. a supersession of the name-binding root. A publisher who completes a ceremony without them is
// locked out of §12.3 authority checkpoints and of §12.1 P2 recovery-through-domain-control until it supersedes —
// and P2 recovery is precisely what a publisher needs when the root key it just generated is later compromised. The
// tool silently narrowed the protocol at the one moment the choice is available.
//
// So this gate is not "keep the CLI in sync". It enumerates the DOMAIN — the builder's own parameter list, read from
// source — against the ceremony call, in both directions.
import { readFileSync } from 'node:fs';

const U = (p) => readFileSync(new URL('../' + p, import.meta.url), 'utf8');
const PROTO = U('packages/ust-protocol/index.mjs');
const CLI = U('packages/ust-cli/index.mjs');

const fail = []; let pass = 0;
const check = (ok, msg) => { if (ok) pass++; else fail.push(msg); };

// a field the ceremony deliberately does not offer must say why HERE, so the boundary is visible rather than absent
const EXCLUDED = {
  role: 'not a choice — buildGenesis fixes it to "name-binding-root" for every genesis',
};

// ── the domain: the value object buildGenesis constructs, read from its source
const body = PROTO.slice(PROTO.indexOf('export const buildGenesis'));
const valueBlock = body.slice(body.indexOf('value: {'), body.indexOf('} } });'));
check(valueBlock.length > 100, 'the buildGenesis value block could not be located — the gate would be vacuous');

const fields = new Set();
// Strip COMMENTS before extracting: the field probe is a regex over the value block, so any prose containing
// `word:` inside it was read as a field. Measured 2026-07-29 — the sentence "role separation is a DECLARED
// refinement: presence of ..." produced a phantom field `refinement` and the gate demanded a ceremony flag for it.
// A gate that can be fooled by a comment reports work that does not exist, which costs exactly what a missed field
// costs: the reader stops believing it.
const codeOnly = valueBlock.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
for (const m of codeOnly.matchAll(/(?:^|[{,\s])([a-z_]+)\s*:/gm)) fields.add(m[1]);
for (const m of valueBlock.matchAll(/^\s*(pub|role),/gm)) fields.add(m[1]);
fields.delete('kind'); fields.delete('value'); fields.delete('key_id'); fields.delete('keys'); fields.delete('threshold');
check(fields.size >= 6, `only ${fields.size} genesis value fields found (${[...fields].join(', ')}) — the probe has gone blind`);

// ── the ceremony must route THROUGH the builder, not beside it
check(/P\.buildGenesis\(/.test(CLI), 'the ceremony does not call P.buildGenesis — a second hand-built genesis shape is exactly how two fields went missing');
check(!/const genValue\s*=/.test(CLI), 'the ceremony still hand-builds a genesis value object beside the builder');

// ── every field reachable, or excluded with a reason
for (const f of fields) {
  if (f in EXCLUDED) { check(EXCLUDED[f].length >= 40, `${f} is excluded with too short a reason to be a decision`); continue; }
  const camel = f.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
  check(new RegExp(`\\b(${f}|${camel})\\b`).test(CLI),
    `buildGenesis can place \`${f}\` in a genesis and the ceremony cannot supply it. This field is settable at ceremony time ONLY — adding it later requires superseding the genesis. Offer it, or exclude it in EXCLUDED with a reason.`);
}

// ── a generated secret that is not persisted is an advertised capability the operator cannot exercise
for (const [gen, file] of [['recoverySigners', 'recovery-key-'], ['caSigner', 'checkpoint-authority-key']]) {
  if (!new RegExp(gen).test(CLI)) continue;
  check(CLI.includes(file), `${gen} is generated but no \`${file}\` is written — the genesis would advertise a capability whose key does not survive the ceremony`);
  check(new RegExp('writeSecret\\(`\\$\\{outDir\\}/' + file).test(CLI), `${file} is not written through writeSecret (0600 + refuse-overwrite), unlike every other ceremony secret`);
}

// ── the file count must be COUNTED, not asserted
check(!/\b(four|five|six|seven) files written/.test(CLI), 'the ceremony summary states a literal file count — it must be derived from what was actually written');

// ── each leg must be able to fail
check(!/\bnonexistent_genesis_field\b/.test(CLI), 'the reachability probe matches a field the CLI lacks');
check(fields.has('cadence') && fields.has('recovery'), 'the field probe lost cadence or recovery — it is no longer reading the real builder');

console.log(`\n  genesis surface   PASS ${pass}   FAIL ${fail.length}   (${fields.size} builder fields: ${[...fields].join(', ')})`);
if (fail.length) { fail.forEach((f) => console.log('    ✗ ' + f)); process.exit(1); }
console.log('  ✓ every field the builder can place is reachable from the ceremony, and every generated secret is persisted');
