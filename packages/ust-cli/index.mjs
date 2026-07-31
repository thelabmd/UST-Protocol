#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// `ust` — the reference CLI. One command hides each ceremony: verify, canon (DX diagnostic), genesis (#37).
// The Go binary (#34) reproduces this surface so `ust` is one static, language-agnostic entrypoint.
//
// The ceremony CORE is exported as pure functions (buildCeremony / checkPublished / cfUpsert / stageSummary /
// encryptKey) so a notary tool is TESTABLE end-to-end without a live network — the 9th-audit regression suite
// (regression.mjs) drives them directly. cmdGenesis is only the readline/network orchestrator around them.
import { createInterface } from 'node:readline/promises';
import { readFileSync, writeFileSync, realpathSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createCipheriv, createDecipheriv, scryptSync, randomBytes, createHash, generateKeyPairSync, sign as edsign } from 'node:crypto';
import * as P from 'ust-protocol';
import { makeSsrfSafeFetch } from 'ust-protocol/ssrf';   // #71 — the SAME Node SSRF guard the MCP uses (resolve→classify→reject private)
import * as W from '@ust-protocol/web-signer';

const arg = (name, def) => { const i = process.argv.indexOf('--' + name); return i > -1 ? (process.argv[i + 1] ?? true) : def; };
const die = (msg) => { console.error('✗ ' + msg); process.exit(1); };
const HEADER = 'UST/1.0; ref=pkg:npm/ust-protocol; web=https://thelabmd.github.io/UST-Protocol/; call=verify(doc,{context:"data"}); hash=domain-separated; trust=resolve-by-name; proves=bytes+key+time';
// ─── THE RAW BOUNDARY (rc.17, external line-review P0-1): every untrusted byte source — file, stdin,
// network, base64 blob — passes through the SAME raw path as the normative verifier. The old shape
// (decodeInput → JSON.parse → P.verify) silently ERASED duplicate JSON members before verification: a
// document the reference raw verifier rejects (E-CANON, duplicate member) verified VALID here. Parse
// happens ONLY after the raw checks.
export const rawTextOf = (raw) => {
  let s = raw.trim(); const m = '———UST(base64)———';
  if (s.includes(m)) s = s.slice(s.lastIndexOf(m) + m.length).trim();
  return s.startsWith('{') || s.startsWith('[') ? s : Buffer.from(s.replace(/\s+/g, ''), 'base64').toString('utf8');
};
// Minimal duplicate-member scanner for the ARRAY shape (a served key log), where verifyJson (single
// document) does not apply directly. The regression suite CROSS-CHECKS it against P.verifyJson on single
// documents so it can never drift silently.
// TODO(protocol): export the scanner from ust-protocol at the next spec rc and delete this copy.
export function scanDupes(text) {
  const stack = []; let i = 0, inStr = false, esc = false, key = null, expectKey = false, buf = '';
  while (i < text.length) {
    const c = text[i];
    if (inStr) {
      if (esc) { esc = false; buf += c; }
      else if (c === '\\') { esc = true; buf += c; }
      else if (c === '"') { inStr = false; if (expectKey && stack.length) key = buf; }
      else buf += c;
      i++; continue;
    }
    if (c === '"') { inStr = true; buf = ''; i++; continue; }
    if (c === '{') { stack.push(new Set()); expectKey = true; i++; continue; }
    if (c === '}') { stack.pop(); expectKey = false; i++; continue; }
    if (c === ':' && key !== null && stack.length) {
      let name; try { name = JSON.parse('"' + key + '"'); } catch { name = key; }
      const top = stack[stack.length - 1];
      if (top.has(name)) return 'duplicate member name: ' + name;
      top.add(name); key = null; expectKey = false; i++; continue;
    }
    if (c === ',') { expectKey = stack.length > 0; key = null; i++; continue; }
    if (c === '[' || c === ']') { expectKey = false; key = null; i++; continue; }
    i++;
  }
  return null;
}
// Verify a SINGLE untrusted document through the normative raw path (admission + duplicate scan + parse
// + verify). Returns { verdict, doc, text } — the caller uses doc ONLY on a valid verdict.
export function verifyRaw(raw, opts = {}) {
  // Buffer path: byte-length admission happens INSIDE verifyJson BEFORE any utf8 decode — the file is
  // never materialized as a string when the transport budget refuses it (F.9 transport refusal).
  if (Buffer.isBuffer(raw)) {
    let i = 0; while (i < raw.length && (raw[i] === 0x20 || raw[i] === 0x09 || raw[i] === 0x0a || raw[i] === 0x0d)) i++;
    const first = raw[i];
    if (first === 0x7b || first === 0x5b) {   // '{' or '['
      const verdict = P.verifyJson(raw, opts);
      if (verdict.result === 'INDETERMINATE' && verdict.reason === 'resource_limit') return { verdict, doc: null, text: null };
      const text = raw.toString('utf8');
      let doc = null; try { doc = JSON.parse(text); } catch { doc = null; }
      return { verdict, doc, text };
    }
    // base64/blob wrapper: bound the ENCODED length before decoding (decoded ≤ encoded)
    const budget = Number(opts.maxInputBytes ?? 67108864);
    if (raw.length > budget) return { verdict: { result: 'INDETERMINATE', reason: 'resource_limit', detail: `raw input ${raw.length} B > input budget ${budget} B` }, doc: null, text: null };
    raw = raw.toString('utf8');
  }
  const text = rawTextOf(raw);
  const verdict = P.verifyJson(text, opts);
  let doc = null; try { doc = JSON.parse(text); } catch { doc = null; }
  return { verdict, doc, text };
}
// Parse an untrusted ARRAY (a served log) fail-closed: duplicate scan on the RAW text, then parse, then each
// entry verifies in the key context. Returns { entries } or { err }.
//
// Both are AUTHORITY-class logs (§F.5e.4): the key role admits EXACTLY `genesis`/`key`/`cadence`, so one parser
// serves both and a data document is refused HERE, at the door that reports having verified the entry.
//
// The earlier justification — "both are signed by genesis/rotation keys, so both admit in the same context" —
// outlived its premise twice: `rotate` was removed (rev97) and key-log mutation became root-only (round 76). And
// it named as a fact what was really the absence of a check: the key role admitted EVERY class, so a key-form
// `class:"observation"` verified here and was only refused one layer down, in the reducer (round 78).
//
// One parser, two logs: the alternative was a second copy differing only in a noun.
export function parseLogRaw(raw, label = 'key log') {
  const text = rawTextOf(raw);
  const dup = scanDupes(text);
  if (dup) return { err: 'E-CANON: ' + dup };
  let arr; try { arr = JSON.parse(text); } catch { return { err: 'not valid JSON' }; }
  if (!Array.isArray(arr)) return { err: `a ${label} must be the JSON ARRAY shape` };
  for (const [i, e] of arr.entries()) {
    const v = P.verify(e, { context: 'key' });
    if (!P.isValid(v)) return { err: `${label} entry ${i} does not VERIFY (${v.error ?? v.result})` };
  }
  return { entries: arr };
}
export const parseKeylogRaw = (raw) => parseLogRaw(raw, 'key log');

// The FLAG/POSITIONAL split, done once against a DECLARED set. `arg()` reads a value as `argv[i + 1]`, so a
// value-taking flag occupies TWO argv slots — and filtering on the `--` prefix alone (the shape this replaces)
// dropped the flag NAME and kept its VALUE, which then became a positional. Measured before the fix:
// `ust stream --genesis <g> <f>` opened <g> as a FRAME, and when <g> verified it was silently admitted into the
// range, so a completeness verdict was computed over a set the operator never described. `stream-consumption-gate`
// enumerates the declared set against the flags the command actually reads, so a NEW flag cannot reintroduce the
// sweep by being forgotten here.
export function positionals(argv, valueFlags) {
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (!t.startsWith('--')) { out.push(t); continue; }
    if (valueFlags.has(t.slice(2)) && i + 1 < argv.length) i++;   // the next token belongs to the flag, never to us
  }
  return out;
}
// Declared per command, because the split is NOT a property of a flag name — `--offline` takes no value while
// `--keylog` does, and a boolean that wrongly claims a value would eat the next positional. Two commands parse
// positionals; both are listed, because fixing the one that was reported and leaving its twin is how a defect
// class survives its own fix.

// A log flag names FILES, and each file is EITHER the SERVED ARRAY — what `ust rotate` and `ust cadence` write, and
// what /.well-known serves — OR a single entry transcript. Accepting only the second is why the artifacts our own
// ceremonies PRODUCE could not be fed to our own range verifier: the consumption dual of the serving gap closed in
// 8229ac7.
//
// Routed on the first non-whitespace BYTE, the same way `verifyRaw` routes, rather than by trying one shape and
// falling back. Trying-then-falling-back would report a broken array as "not a valid entry either", burying the real
// error under the wrong one — and it would materialize the file as a string before the single-doc path's byte-length
// admission had a chance to refuse it.
function readLogFiles(flag, raw) {
  return String(raw).split(',').flatMap((f) => {
    const name = f.trim();
    const bytes = readFileSync(name);
    let i = 0; while (i < bytes.length && (bytes[i] === 0x20 || bytes[i] === 0x09 || bytes[i] === 0x0a || bytes[i] === 0x0d)) i++;
    if (bytes[i] === 0x5b) {                                        // '[' — the served log
      const parsed = parseLogRaw(bytes.toString('utf8'), `--${flag}`);
      if (parsed.err) die(`--${flag} ${name}: ${parsed.err}`);
      return parsed.entries;
    }
    const { verdict, doc } = verifyRaw(bytes);                      // '{' — one entry, the degenerate case
    if (!P.isValid(verdict)) die(`--${flag} entry ${name} does not VERIFY (${verdict.error ?? verdict.result})`);
    return [doc];
  });
}

export const STREAM_VALUE_FLAGS = new Set(['genesis', 'checkpoint', 'cadence-log', 'keylog']);
export const FORKCHOICE_VALUE_FLAGS = new Set(['genesis', 'keylog']);
export const FORKCHOICE_BOOL_FLAGS = new Set(['no-fork-confirmed', 'offline']);
// Convenience parse (blob/base64 → object) for bytes this tool built ITSELF or already admitted through
// verifyRaw/parseKeylogRaw. NEVER the entry point for untrusted verification input.
export const decodeInput = (raw) => JSON.parse(rawTextOf(raw));
const nowFrame = () => W.nowFrame();
// The verify context follows the record's own class: a genesis/key-log frame verifies as 'key', everything
// else as 'data'. This is why `ust verify ust-genesis` just works — no one should need to know the context.
export const contextFor = (doc) => (doc?.state?.id?.class === 'genesis' || doc?.state?.id?.class === 'key') ? 'key' : 'data';

// ─── ceremony CORE (pure, exported — a notary tool must be verifiable by tests, not just by eye) ─────────

// Hidden passphrase input (line-review P1: readline echoed the root passphrase to the terminal). Raw-mode
// character loop with '*' echo in a tty; falls back to the visible ask (with a loud warning) elsewhere.
// ONE reader lifecycle, because `close()` is not enough on a real terminal.
//
// MEASURED, and this is what broke an air-gapped ceremony twice: with `terminal: true` — which is what stdin gets
// in an actual terminal — readline attaches BOTH a 'data' and a 'keypress' listener, and `close()` removes only the
// keypress one. The 'data' listener SURVIVES. So askHidden's guard, which refuses to read a secret while another
// reader owns stdin, kept firing after a correct close. My own measurement missed it because I ran it under a pipe,
// where `terminal` is false and close() does drop the listener — the tested path was not the operator's path.
//
// closeReader undoes exactly what openReader added: the listener sets are snapshotted at creation and only the NEW
// ones are removed. A foreign listener — a signal handler, a parent harness — is never touched.
const READER_ADDED = new WeakMap();

export function openReader(createInterface) {
  const before = { data: [...process.stdin.listeners('data')], keypress: [...process.stdin.listeners('keypress')] };
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  READER_ADDED.set(rl, before);
  return rl;
}

/** Close a reader AND hand stdin back — return null so the caller's handle is cleared in one expression. */
export function closeReader(rl) {
  if (!rl) return null;
  const before = READER_ADDED.get(rl) ?? { data: [], keypress: [] };
  try { rl.close(); } catch { /* already closed */ }
  for (const ev of ['data', 'keypress']) {
    for (const l of process.stdin.listeners(ev)) if (!before[ev].includes(l)) process.stdin.removeListener(ev, l);
  }
  // …and PAUSE it, but only if nobody is left reading. A resumed stdin with no reader holds the event loop open, so
  // a command that has finished never exits: everything prints, the shell returns no prompt, and the next thing the
  // operator types goes into a dead process. Conditional, because pausing a stream a concurrent reader still needs
  // would starve it.
  if (process.stdin.listenerCount('data') === 0 && process.stdin.listenerCount('readable') === 0) process.stdin.pause();
  return null;
}

export async function askHidden(q, fallbackAsk) {
  // askHidden must own stdin. A readline interface created BEFORE this call takes stdin over and echoes the
  // line ITSELF — its echo wins over this raw-mode loop, so the passphrase appears in plaintext while the code
  // looks correct. Measured 2026-07-27: the owner ran the cadence ceremony and watched the root passphrase print.
  // Every caller now builds its readline LAZILY, and this guard makes a future eager one loud instead of silent.
  if (process.stdin.listenerCount('data') > 0 || process.stdin.listenerCount('keypress') > 0)
    throw new Error('askHidden: another reader owns stdin (a readline interface is open) — it would ECHO the secret. Create the interface lazily, after this call.');
  if (!process.stdin.isTTY) { console.log('  ⚠️  no tty — the passphrase WILL echo'); return fallbackAsk(q); }
  process.stdout.write(q);
  return await new Promise((resolve) => {
    const chars = [];
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    const wasPaused = stdin.isPaused();   // restore what we found: resuming a paused stdin and leaving it resumed
                                          // keeps the event loop alive, so the command finishes and never exits
    stdin.setRawMode(true); stdin.resume();
    // A data event is a CHUNK, not a keystroke. Treating it as one character means a PASTED passphrase — which is
    // how anyone enters a strong one — arrives as a single string equal to neither a terminator nor a character:
    // it is pushed whole, one asterisk is printed, and the prompt NEVER returns. Measured under a real pty: the
    // ceremony hung exactly there. Iterate by CODE POINT, never by UTF-16 unit, or a non-ASCII passphrase would
    // split mid-character.
    const onData = (b) => {
      for (const c of b.toString('utf8')) {
        if (c === '\r' || c === '\n') { stdin.setRawMode(wasRaw); stdin.removeListener('data', onData); if (wasPaused) stdin.pause(); process.stdout.write('\n'); return resolve(chars.join('')); }
        if (c === '\u0003') { stdin.setRawMode(wasRaw); process.stdout.write('\n'); process.exit(130); }
        if (c === '\u007f' || c === '\b') { if (chars.length) { chars.pop(); process.stdout.write('\b \b'); } continue; }
        chars.push(c); process.stdout.write('*');
      }
    };
    stdin.on('data', onData);
  });
}

// gold IS the hardware tier — one refusal text, used by the core AND the interview (single source).
export const GOLD_REFUSAL = 'gold is a HARDWARE ceremony (pkcs11 / air-gapped signer). This CLI cannot drive one yet and will not pretend — run --profile silver (software root, encrypted backup), then re-root to hardware via a §12.1 supersession when ready.';

export const encryptKey = (pkcs8, pass) => {
  const salt = randomBytes(16), iv = randomBytes(12), key = scryptSync(pass, salt, 32);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(pkcs8), c.final()]);
  return Buffer.concat([salt, iv, c.getAuthTag(), ct]).toString('base64');
};
// inverse of encryptKey — throws (GCM auth) on a wrong passphrase / corrupt backup (never a silent bad key).
export const decryptKey = (b64, pass) => {
  const buf = Buffer.from(b64, 'base64');
  const salt = buf.subarray(0, 16), iv = buf.subarray(16, 28), tag = buf.subarray(28, 44), ct = buf.subarray(44);
  const d = createDecipheriv('aes-256-gcm', scryptSync(pass, salt, 32), iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
};

// Build genesis + key-log[0] (adds an operational key) and SELF-CHECK both (fail-closed, 9th audit #6):
// a ceremony tool must never emit an output it hasn't verified. Throws before returning if either fails.
// `warnings` carries the gold ASSURANCE LIMIT so the orchestrator (and the test) can assert it (9th audit #5).
export async function buildCeremony({ domain, profile = 'silver', maxP, maxBytes = null, cadence = null, checkpointAuthority = null, recovery = null, roles = null, signerRef }) {
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
  // §12.1 — the ceremony builds its genesis THROUGH the protocol builder, never beside it. Two hand-maintained
  // shapes of one document is how `checkpoint_authority` and `recovery` came to exist in `buildGenesis` and stay
  // unreachable from the only tool that performs the ceremony — and BOTH can be set at ceremony time only, so a
  // publisher that misses them is locked out until a supersession. genesis-surface-gate enumerates the builder's
  // fields against this call, so a field added there cannot silently skip the ceremony again.
  const genesis = await W.seal(P.buildGenesis(
    { domain_shard: domain, ust_id, key_id: root.key_id }, time, root.pub,
    maxP ?? undefined, maxBytes ?? undefined, cadence ?? undefined,
    checkpointAuthority ?? undefined, recovery ?? undefined, roles ?? undefined,
  ), root);
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
  // A ceremony must never emit an output it has not verified — and VERIFYING the two documents is weaker than the
  // property they exist for. MEASURED: a genesis carrying `roles: []` verifies VALID:LIGHT on its own and is then
  // REFUSED by `resolveKeys` (E-GENESIS, the array must be non-empty), so this self-check would have signed and
  // published an identity from which no consumer could ever resolve a key. The builder now cannot produce that
  // genesis, and this leg makes the ceremony check the property rather than its shadow: the pair must RESOLVE.
  const selfKeys = P.resolveKeys(genesis, [keylog0]);
  if (selfKeys.error) throw new Error('self-check FAILED: the genesis + key-log do not RESOLVE (' + selfKeys.error + ': ' + (selfKeys.detail ?? '') + ') — they verify as documents but no consumer could resolve a key from them');
  if (!(selfKeys.active?.size >= 2)) throw new Error('self-check FAILED: the resolved key set holds ' + (selfKeys.active?.size ?? 0) + ' active key(s) — a ceremony must leave the root AND the operational key active');
  return { genesis, keylog0, genHash, op, opPkcs8, pkcs8, warnings };
}

// Fail-closed check of the published well-known: it must VERIFY and its content_hash must MATCH the genesis
// we built (a semantic UST match, not a transport byte-compare — 9th audit #1). Throws on any mismatch.
export function checkPublished(liveText, genHash) {
  const { verdict, doc } = verifyRaw(liveText);   // the normative raw path — duplicates/admission included
  if (!P.isValid(verdict)) throw new Error('published document does not VERIFY' + (verdict.error ? ` (${verdict.error}${verdict.detail ? ' — ' + verdict.detail : ''})` : ''));
  if (P.contentHash(doc) !== genHash) throw new Error('published document is not this genesis (content_hash differs) — republish exactly the ust-genesis file');
  return doc;
}

// Chain sanity for a key log against ITS genesis (fail-closed before any deploy): every entry verifies
// in the key context, entry 0 chains to the genesis content_hash, each next entry chains to the previous.
// (Full revocation/authority semantics live in P.resolveAuthority — this is the publishing gate.)
export function validateKeylogChain(genesisDoc, entries) {
  let prev = P.contentHash(genesisDoc);
  for (const [i, e] of entries.entries()) {
    const v = P.verify(e, { context: 'key' });
    if (!P.isValid(v)) return `key-log entry ${i} does not VERIFY (${v.error ?? v.result})`;
    if (e.state?.provenance?.prev !== prev) return `key-log entry ${i} does not chain (prev ≠ ${i === 0 ? 'genesis' : 'entry ' + (i - 1)} content_hash)`;
    if (e.state?.id?.domain_shard !== genesisDoc.state?.id?.domain_shard) return `key-log entry ${i} belongs to a different domain_shard`;
    prev = P.contentHash(e);
  }
  return null;
}

// Independent DoH readback of the _ust TXT — shared by the cf-api path AND the by-hand path, so BOTH
// roads get the same confirmation discipline (the record is confirmed by a resolver, never by the API
// that wrote it). Returns seen/not — the CALLER decides whether absence is fatal (cf-api) or a warning
// with a re-attest pointer (by-hand: registrar TTLs can be long, the ceremony must not strand the user).
export async function dohConfirmTxt({ domain, genHash, fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), attempts = 6, delayMs = 3000, onAttempt = null }) {
  for (let i = 0; i < attempts; i++) {
    const doh = await fetchImpl(`https://cloudflare-dns.com/dns-query?name=_ust.${domain}&type=TXT`, { headers: { accept: 'application/dns-json' } }).then((r) => r.json()).catch(() => ({}));
    if ((doh.Answer || []).some((a) => (a.data || '').replace(/"/g, '').includes(genHash))) return true;
    onAttempt?.(i + 1, attempts);
    if (i < attempts - 1) await sleep(delayMs);
  }
  return false;
}

// Cloudflare one-click: UPSERT the _ust TXT (find → PUT if present, else POST) then CONFIRM it via a
// DNS-over-HTTPS readback (idempotent + fail-closed, 9th audit #7). fetchImpl/sleep are injected so the
// regression suite exercises the update-path and the readback-failure-path with no live network.
export async function cfUpsert({ domain, txt, genHash, token, fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), onAttempt = null }) {
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
  // UPDATE patience (live lesson, 2nd real ceremony): on an UPDATE the public resolver keeps serving the
  // OLD value until its TTL (300 s) expires — 18 s of readback fails a perfectly good write. Wait through
  // a full TTL window, narrated; a CREATE confirms on the first tries as before.
  const seen = await dohConfirmTxt({ domain, genHash, fetchImpl, sleep, attempts: existing ? 24 : 6, delayMs: existing ? 15000 : 3000, onAttempt });
  if (!seen) throw new Error('CF accepted the record, but the public resolver still serves the OLD value (resolver TTL cache — an updated record can take ~5 min to converge). Wait a few minutes and RE-RUN the ceremony: it is idempotent and rewrites the TXT and the worker consistently.');
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
// The SELF-HOSTED road, written out. The §20.1 contract is deliberately vendor-neutral — "properties, not vendors"
// — and until now the only publish adapter was Cloudflare, so an operator on their own stack got a refusal about a
// missing token and no map at all. Worse for a supersession: the WITNESS is a successor computed from what is live,
// and nobody can build that by hand. So this road assembles the same four artifacts the CF adapter would serve,
// writes them to disk, and hands over the exact contract plus the command that ATTESTS it.
// HOW THE OPERATOR ACTUALLY INVOKED THIS. Every instruction the tool prints used to begin with `ust `, which is
// only correct when the package is installed globally. Someone running it straight from a checkout — which is what
// an air-gapped ceremony looks like, and what the owner did — copied a printed command and got
// `zsh: command not found: ust`. A printed instruction has to be runnable in the context that printed it.
export function invocation() {
  const argv1 = process.argv[1] ?? '';
  const base = argv1.split(/[/\\]/).pop() ?? '';
  return base === 'ust' ? 'ust' : `node ${argv1}`;
}

export function selfHostedPlan({ domain, outDir, genHash, artifacts }) {
  const served = Object.entries(artifacts).filter(([, v]) => v != null).map(([k]) => k);
  return [
    '',
    '  ══════════════════════════════════════════════',
    '  🏗  SELF-HOSTED — the files are written; the serving is yours',
    '  ══════════════════════════════════════════════',
    `  identity      ${genHash}`,
    `  written       ${served.length} artifact(s) to ${outDir}/`,
    '',
    '  1️⃣  SERVE each file at its well-known path, byte for byte:',
    ...served.map((a) => `       ${outDir}/ust-${a}  →  https://${domain}/.well-known/ust-${a}`),
    '',
    '  2️⃣  THE CONTRACT (§20.1) — properties, not vendors; any stack conforms:',
    '       · methods: GET and HEAD · content-type: application/json',
    '       · Cache-Control: public, max-age=300 — the URL points at the CURRENT document, so a rotation',
    '         must converge; cache longer ONLY if you purge on rotation',
    '       · an unknown query parameter must NOT change the response or its cache key (cache key = path)',
    '       · the SAME bytes from every vendor you serve from — a mirror that differs is not a mirror',
    '',
    '  3️⃣  DNS — one TXT record, the pointer that binds the name to this identity:',
    `       _ust.${domain}   TXT   "ust-genesis=${genHash}"`,
    '',
    '  4️⃣  ATTEST it — from anywhere, trusting nobody, including yourself:',
    `       ${invocation()} discovery ${domain}`,
    '       It fetches every surface, checks the bytes against these files, probes the query-robustness',
    '       rule and reads the DNS pin. A pass is evidence; your own assertion is not.',
    '',
    '  examples for common stacks:',
    `       static host:  copy the files into  <webroot>/.well-known/`,
    '       nginx:        location = /.well-known/ust-genesis { alias /srv/ust/ust-genesis;',
    '                       default_type application/json; add_header Cache-Control "public, max-age=300"; }',
    '       caddy:        handle /.well-known/ust-* { root * /srv/ust; file_server }',
    '  ══════════════════════════════════════════════',
  ];
}

export function manualServingGuide(domain, outDir) {
  return [
    `  make  https://${domain}/.well-known/ust-genesis  return the EXACT bytes of ${outDir}/ust-genesis`,
    '  the §20.1 serving contract — PROPERTIES, not vendors; any stack conforms:',
    '    · methods: GET (+ HEAD) · content-type: application/json',
    '    · BOUNDED caching:  Cache-Control: public, max-age=300  — the URL is a pointer to the CURRENT',
    '      genesis; a key rotation must converge (cache longer ONLY if you purge on rotation)',
    '    · unknown query params must NOT change the response or its cache key (cache key = path)',
    '  examples:',
    '    · static host: upload the file to  <webroot>/.well-known/ust-genesis',
    '    · serve the key log the same way at  /.well-known/ust-keylog  (a JSON array — APPEND on rotation)',
    '    · nginx:  location = /.well-known/ust-genesis { alias /srv/ust/ust-genesis;',
    '              default_type application/json; add_header Cache-Control "public, max-age=300"; }',
  ];
}

// ─── CF one-click adapter (§20.1 CONVENIENCE path — the contract is infra-agnostic; this is ONE way) ───
// The genesis is EMBEDDED in the worker (an immutable ~1–2 KB document): no bucket, no extra credential
// scope, the worker IS the content. Query-robustness is NATIVE — the edge-cache key is the PATH, so an
// unknown ?param can never mint a new cache entry (§20.1 property, implemented at the layer that owns it).
// The genesis-log for the witness endpoint (#68): the publisher's OWN append-only record of every genesis
// for this name. Phase 1 carries the single active genesis; an anchor (Bitcoin OTS) is attached once its
// stamp is final — until then a verifier honestly reports "HIGH pending" (it cannot cross-check yet).
// A witness log is DERIVED FROM THE PRIOR ONE, never regenerated. Rebuilding it from the new genesis alone would
// delete the previous identity, anchors and all — §12.1: "supersession is expressed by ADDING `superseded_by` and a
// successor entry, never by removal." The rule and the successor construction live in the protocol (witnessSuccessor
// / witnessNoShrink), so the ceremony, the deploy path and any consumer's mirror all apply one rule rather than three
// copies of it. `priorLogText` absent ⇒ a first ceremony; present ⇒ a supersession that must survive the same
// no-shrink test the mirror will apply on the way in.
export function buildWitnessLog(genesisText, anchors = null, priorLogText = null) {
  const g = JSON.parse(genesisText);
  let prior = null;
  if (priorLogText != null) {
    try { prior = typeof priorLogText === 'string' ? JSON.parse(priorLogText) : priorLogText; }
    catch { throw new Error('the prior witness log is unparseable — refusing to replace a history that cannot be read'); }
  }
  const r = P.witnessSuccessor(prior, { domain_shard: g.state.id.domain_shard, content_hash: P.contentHash(g), anchors });
  if (r.error) throw new Error('witness successor refused: ' + r.error);
  return JSON.stringify(r.log);
}

// Log a genesis leaf-root into Sigstore Rekor (a public transparency log) and return the rekor anchor.
// The Rekor entry is signed by an EPHEMERAL key: the witness value is the immutable, timestamped INCLUSION
// of the genesis leaf-root in a public log — NOT the identity of who logged it (that is the genesis's own
// signature, resolved separately). Convention: the artifact is the root's hex string; Rekor stores its
// sha256. Seconds, not Bitcoin's hours.
export async function logToRekor(rootHex, { fetchImpl = fetch, api = 'https://rekor.sigstore.dev' } = {}) {
  const artifact = Buffer.from(rootHex.replace(/^sha256:/, ''), 'utf8');
  const hash = createHash('sha256').update(artifact).digest('hex');
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signature = edsign('sha256', artifact, privateKey).toString('base64');
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const body = { apiVersion: '0.0.1', kind: 'hashedrekord', spec: { data: { hash: { algorithm: 'sha256', value: hash } }, signature: { content: signature, publicKey: { content: Buffer.from(pem).toString('base64') } } } };
  const r = await fetchImpl(`${api}/api/v1/log/entries`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error('Rekor POST failed: HTTP ' + r.status + ' ' + (await r.text()).slice(0, 120));
  const entry = Object.values(await r.json())[0];
  return { substrate: 'rekor', logIndex: entry.logIndex, body: entry.body, inclusionProof: entry.verification.inclusionProof, integratedTime: entry.integratedTime };
}

// The §20.1 discovery SET, in the order a verifier resolves it: the identity, its key history, the grid it
// declares, the no-fork evidence. ONE list rather than four hand-copied blocks — the shape that let cadence
// ship (3d58537) with a command that PRODUCES `./ust-cadence` and no path that SERVES it, while 40 gates
// stayed green because each asserted a capability exists, never that its artifact has somewhere to land.
// `discovery-serving-gate` enumerates this list, so a fifth member fails until it is wired end to end.
export const DISCOVERY_ARTIFACTS = ['genesis', 'keylog', 'cadence', 'witness'];

// HOW each served artifact comes to exist — declared, because the difference is where evidence gets destroyed.
//
// A LOADED artifact is READ from somewhere the operator controls: if the read fails, nothing is served and the
// failure is visible. A DERIVED artifact is CONSTRUCTED by this tool, and construction has a second failure mode
// that loading does not — it can succeed while producing LESS than what was already published. That is exactly what
// happened: the witness log was rebuilt from the genesis alone, so every deploy silently overwrote the anchors, and
// a re-ceremony would have deleted the predecessor entirely.
//
// So a DERIVED artifact carries an obligation a loaded one does not: it must EXTEND what is live, never replace it,
// and it must be checkable against the same monotonicity rule a mirror applies on the way in. artifact-origin-gate
// enumerates this table against DISCOVERY_ARTIFACTS in both directions and holds the obligation to the derivation.
export const ARTIFACT_ORIGIN = {
  genesis: 'loaded',    // handed in by the caller — the ceremony wrote it; this tool never mints one here
  keylog:  'loaded',    // handed in by the caller, append-only, produced by `ust rotate`
  cadence: 'loaded',    // read from the log beside the genesis; absent ⇒ not served, never invented
  witness: 'derived',   // CONSTRUCTED from the live log — the only one, and the one that lost evidence
};

// A derived artifact must be built from the prior it extends. Named here so the gate checks a CONTRACT rather than
// a call signature it happened to read once.
export const DERIVED_REQUIRES_PRIOR = { witness: 'buildWitnessLog(genesisText, anchors, priorLog)' };

export function buildWorkerScript(genesisText, keylogText = null, witnessText = null, cadenceText = null) {
  // STATELESS by design (live lesson, 3rd ceremony): the first template cached its response at the edge
  // for 24 h — a redeploy then kept serving the PREVIOUS genesis (Cache API survives worker versions).
  // The content is already IN the worker; a cache saved nothing (the invocation happens either way) and
  // created a whole staleness bug-class. No state ⇒ a redeploy is live instantly; max-age is BOUNDED so
  // downstream caches converge within the same window as the DNS TTL (§20.1 propagation bound).
  //
  // The KEY LOG rides next to the genesis (owner catch: a verifier needs BOTH to resolve the name — the
  // adapter must not leave step-3-of-HIGH as homework). Served as a JSON ARRAY so a rotation is an
  // APPEND + redeploy — the log only ever GROWS; it is never rewritten. The WITNESS log (#68) rides too at
  // /.well-known/ust-witness — the no-fork evidence surface.
  return `// ust identity serving worker — generated by @ust-protocol/cli (§20.1 serving contract, CF adapter)
const GENESIS = ${JSON.stringify(genesisText)};
const KEYLOG = ${keylogText === null ? 'null' : JSON.stringify(keylogText)};
const CADENCE = ${cadenceText === null ? 'null' : JSON.stringify(cadenceText)};
const WITNESS = ${witnessText === null ? 'null' : JSON.stringify(witnessText)};
// A TABLE, not a chain of comparisons: a new discovery artifact is a row, and an absent one stays null →
// 404, which is the very distinction \`ust cadence\` reads to tell ABSENT (first declaration) from UNREADABLE.
const SERVED = { '/.well-known/ust-genesis': GENESIS, '/.well-known/ust-keylog': KEYLOG, '/.well-known/ust-cadence': CADENCE, '/.well-known/ust-witness': WITNESS };
export default {
  async fetch(req) {
    const u = new URL(req.url);
    const body = Object.hasOwn(SERVED, u.pathname) ? SERVED[u.pathname] : null;
    if (body === null) return new Response('not found', { status: 404 });
    if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('method not allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
    // §20.1 query-robustness holds trivially: identical bytes for ANY query — nothing varies, nothing is stored.
    // CORS open: the discovery pair is PUBLIC identity data — browser verifiers (the web ladder) must be
    // able to auto-resolve it cross-origin. GET/HEAD only; opening reads costs nothing.
    return new Response(req.method === 'HEAD' ? null : body, { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'public, max-age=300', 'access-control-allow-origin': '*' } });
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
export function buildWranglerProject({ domain, genesisText, keylogText = null, witnessText = null, cadenceText = null }) {
  return {
    'worker.mjs': buildWorkerScript(genesisText, keylogText, witnessText, cadenceText),
    'wrangler.toml': [
      `name = "ust-genesis-${domain.replaceAll('.', '-')}"`,
      'main = "worker.mjs"',
      'compatibility_date = "2026-01-01"',
      'workers_dev = false',
      `routes = [${servedArtifacts({ genesisText, keylogText, cadenceText, witnessText })
        .map((a) => `{ pattern = "${domain}/.well-known/ust-${a}*", zone_name = "${domain}" }`).join(', ')}]`,
    ].join('\n') + '\n',
  };
}

// Which discovery artifacts this deploy actually carries, in DISCOVERY_ARTIFACTS order. The worker answering a
// path Cloudflare never routes to it is a real past defect (line-review P0-3, the key-log); one list now feeds
// BOTH the dispatch table and the routes, so the two cannot drift apart again.
// A deploy is constructed from the COMPLETE discovery set or not at all. Every call site used to assemble its own
// arguments, so every call site could forget one — and three of five did: cmdWitness --deploy and both cmdGenesis
// sites passed neither the cadence log nor the witness anchors, so a deploy from either NULLED /.well-known/ust-cadence
// and DESTROYED the served Rekor/OTS anchors. That is not three bugs; it is one missing assembler, found three times.
// Nothing here enumerates artifacts at a call site any more: they ask for the set and pass it whole.
export async function collectServed({ domain, genesisText, genPath, keylogText = null, witnessFile = null, cadenceFile = null, fetchImpl = fetch, log = () => {} }) {
  const genHash = P.contentHash(JSON.parse(genesisText));
  const anchorsOf = (text) => { try { const w = JSON.parse(text); const a = w?.genesis_log?.find((e) => e.content_hash === genHash)?.anchors; return Array.isArray(a) && a.length ? a : null; } catch { return null; } };

  // PRESERVE first, and preserve the WHOLE log, not just its anchors. Keeping only the anchors sufficed while a
  // domain had one identity forever; the moment a genesis is superseded, a log rebuilt from the new one alone
  // DELETES the predecessor — which §12.1 forbids and a mirror refuses. So the live log is carried forward as the
  // prior and buildWitnessLog derives a successor from it.
  let anchors = null, priorLog = null;
  try {
    const r = await fetchImpl(`https://${domain}/.well-known/ust-witness`, { signal: AbortSignal.timeout(10000) });
    if (r.ok) {
      priorLog = await r.text();
      anchors = anchorsOf(priorLog);
      if (anchors) log(`  ℹ️  preserving ${anchors.length} witness anchor(s) from the live log`);
      let n = 0; try { n = JSON.parse(priorLog).genesis_log?.length ?? 0; } catch { /* shape reported downstream */ }
      if (n > 1) log(`  ℹ️  carrying forward ${n} genesis entries — this domain has superseded before`);
    }
  } catch { /* unreachable ⇒ nothing live to preserve */ }
  // RESTORE second: a local log may still hold what an earlier deploy destroyed.
  if (!anchors || !priorLog) {
    const wPath = witnessFile || (genPath ? genPath.replace(/[^/\\]+$/, 'ust-witness') : null);
    if (wPath) {
      try {
        const text = readFileSync(wPath, 'utf8');
        priorLog ??= text;
        anchors ??= anchorsOf(text);
        if (anchors) log(`  ℹ️  restoring ${anchors.length} witness anchor(s) from ${wPath}`);
      } catch { if (witnessFile) die('could not read --witness ' + wPath); }
    }
  }

  let cadenceText = null;
  const cadPath = cadenceFile || (genPath ? genPath.replace(/[^/\\]+$/, 'ust-cadence') : null);
  if (cadPath) {
    try {
      const parsed = parseLogRaw(readFileSync(cadPath, 'utf8'), '--cadence-log');
      if (parsed.err) { if (cadenceFile) die('could not admit --cadence-log ' + cadPath + ': ' + parsed.err); }
      else cadenceText = JSON.stringify(parsed.entries);
    } catch { if (cadenceFile) die('could not read --cadence-log ' + cadPath); }
  }

  return { genesisText, keylogText, cadenceText, witnessText: buildWitnessLog(genesisText, anchors, priorLog) };
}

export function servedArtifacts({ genesisText, keylogText = null, cadenceText = null, witnessText = null }) {
  const t = { genesis: genesisText, keylog: keylogText, cadence: cadenceText, witness: witnessText };
  return DISCOVERY_ARTIFACTS.filter((a) => t[a] !== null && t[a] !== undefined);
}

// The MINIMAL wrangler OAuth consent for this deploy — 5 scopes, not wrangler's default 28. The default
// consent asks for wrangler's WHOLE toolbox (D1/Pages/Queues/Email/…) because OAuth scopes belong to the
// CLIENT, not the task; `--scopes` narrows the grant to exactly what deploying a worker+route needs.
export const WRANGLER_LOGIN_CMD = 'npx wrangler login --scopes account:read user:read workers_scripts:write workers_routes:write zone:read';

// OAuth half: deploy via `npx wrangler deploy` — wrangler owns the browser-login flow (the CF OAuth client
// is wrangler-only; a third-party CLI cannot run that flow itself, so we DELEGATE instead of imitating).
// stdio is inherited so the user SEES the login. execImpl/writeImpl injected — testable without a network.
// The ONE publish gate (both adapters): the genesis passes the normative RAW path, must BE class:genesis
// for THIS domain, and a key log (when given) must verify entry-by-entry AND chain from this genesis —
// all BEFORE any network write. Line-review P0-2/P0-3: nothing untrusted rides to a deploy unverified.
export function validatePublishInputs({ domain, genesisText, keylogText = null }) {
  const { verdict, doc } = verifyRaw(genesisText);
  if (!P.isValid(verdict)) throw new Error('refusing to publish: the genesis does not VERIFY' + (verdict.error ? ` (${verdict.error})` : ''));
  if (doc.state?.id?.class !== 'genesis') throw new Error(`refusing to publish: class:${doc.state?.id?.class ?? '?'} is not a genesis`);
  if (doc.state?.id?.domain_shard !== domain) throw new Error(`refusing to publish: genesis domain_shard ${doc.state?.id?.domain_shard ?? '?'} ≠ ${domain}`);
  let entries = null;
  if (keylogText !== null) {
    const parsed = parseKeylogRaw(keylogText);
    if (parsed.err) throw new Error('refusing to publish the key log: ' + parsed.err);
    const chainErr = validateKeylogChain(doc, parsed.entries);
    if (chainErr) throw new Error('refusing to publish the key log: ' + chainErr);
    entries = parsed.entries;
  }
  return { doc, genHash: P.contentHash(doc), entries };
}

export async function wranglerDeploy({ domain, genesisText, keylogText = null, witnessText = null, cadenceText = null, execImpl = null, writeImpl = null }) {
  const { genHash } = validatePublishInputs({ domain, genesisText, keylogText });
  const files = buildWranglerProject({ domain, genesisText, keylogText, witnessText, cadenceText });
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'ust-cf-'));
  const write = writeImpl ?? ((p, c) => writeFileSync(p, c));
  for (const [name, content] of Object.entries(files)) write(join(dir, name), content);
  const exec = execImpl ?? (async (cwd) => {
    const { spawnSync } = await import('node:child_process');
    // No `npx` — that would DOWNLOAD-and-run wrangler ad-hoc (a silent external fetch + arbitrary-code risk). Call the
    // LOCAL wrangler the operator installed (declared as an OPTIONAL PEER). ENOENT → tell them to install it, never fetch.
    const r = spawnSync('wrangler', ['deploy'], { cwd, stdio: 'inherit' });
    if (r.error && r.error.code === 'ENOENT') { console.error('`wrangler` not found on PATH. UST never fetches a tool for you — that is deliberate.'
        + '\n  · already installed in another project? point PATH at it for this one command:'
        + '\n      PATH="<that repo>/node_modules/.bin:$PATH" ' + invocation() + ' publish cf …'
        + '\n  · install it:  npm i -g wrangler   (needs sudo when the npm prefix is /usr/local)'
        + '\n  · or skip the vendor entirely:  ' + invocation() + ' publish self   — writes the four'
        + '\n    artifacts, including the witness successor, for you to serve on your own stack'); return 127; }
    return r.status ?? 1;
  });
  const code = await exec(dir);
  if (code !== 0) throw new Error('wrangler deploy failed (not logged in? run the MINIMAL-scope browser login and re-run):\n  ' + WRANGLER_LOGIN_CMD + '\n  (5 scopes — not wrangler\'s default 28; `wrangler logout` revokes the grant after the ceremony)');
  return { genHash, script: `ust-genesis-${domain.replaceAll('.', '-')}`, route: `${domain}/.well-known/ust-genesis*`, dir };
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
export async function cfPublish({ domain, genesisText, keylogText = null, witnessText = null, cadenceText = null, token, flipProxy = false, fetchImpl = fetch }) {
  if (!token) throw new Error('cf adapter needs CF_TOKEN (Workers Scripts:Edit + Workers Routes:Edit + DNS:Edit for this zone) — or split the scopes: `--auth wrangler` + a DNS-only token (' + CF_DNS_TOKEN_URL + ')');
  const { genHash } = validatePublishInputs({ domain, genesisText, keylogText });
  const cf = (path, init) => fetchImpl('https://api.cloudflare.com/client/v4' + path, { ...init, headers: { Authorization: 'Bearer ' + token, ...(init?.headers) } }).then((r) => r.json());

  const zone = (await cf(`/zones?name=${domain}`)).result?.[0];
  if (!zone) throw new Error('CF zone not found / token cannot see ' + domain);
  const accountId = zone.account?.id;
  if (!accountId) throw new Error('zone carries no account id — token needs zone read access');

  // 1. worker script (PUT = create-or-replace, idempotent; module syntax)
  const script = `ust-genesis-${domain.replaceAll('.', '-')}`;
  const form = new FormData();
  form.append('metadata', new Blob([JSON.stringify({ main_module: 'worker.mjs', compatibility_date: '2026-01-01' })], { type: 'application/json' }), 'metadata');
  form.append('worker.mjs', new Blob([buildWorkerScript(genesisText, keylogText, witnessText, cadenceText)], { type: 'application/javascript+module' }), 'worker.mjs');
  const up = await cf(`/accounts/${accountId}/workers/scripts/${script}`, { method: 'PUT', body: form });
  if (!up.success) throw new Error('worker upload failed: ' + (up.errors?.[0]?.message || '?'));

  // 2. route upsert (list → PUT if present, POST if absent — same idempotence as cfUpsert), ONE pass over the
  // set this deploy carries. line-review P0-3 was exactly this drift: the wrangler road created BOTH routes,
  // the API road only the genesis one, so the worker answered a path Cloudflare never routed to it. A loop over
  // `servedArtifacts` cannot drift from the dispatch table `buildWorkerScript` was handed the same inputs for.
  const pattern = `${domain}/.well-known/ust-genesis*`;
  const routes = (await cf(`/zones/${zone.id}/workers/routes`)).result || [];
  const existing = routes.find((r) => r.pattern === pattern);
  for (const a of servedArtifacts({ genesisText, keylogText, cadenceText, witnessText })) {
    const p = `${domain}/.well-known/ust-${a}*`;
    const prior = routes.find((r) => r.pattern === p);
    const body = JSON.stringify({ pattern: p, script });
    const rt = prior
      ? await cf(`/zones/${zone.id}/workers/routes/${prior.id}`, { method: 'PUT', body, headers: { 'content-type': 'application/json' } })
      : await cf(`/zones/${zone.id}/workers/routes`, { method: 'POST', body, headers: { 'content-type': 'application/json' } });
    if (!rt.success) throw new Error(`${a} route upsert failed: ` + (rt.errors?.[0]?.message || '?'));
  }

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

  // (1) well-known: fetch → the normative RAW path (duplicates/admission) → it must BE a genesis and it
  // must be THIS domain's genesis (line-review P0-2: a valid observation from a foreign identity served
  // at the well-known previously attested). content_hash pinned when --expect is given.
  let baseline = null, hash = null, genesisCadence = null;   // §11.3: the grid can be declared IN the genesis
  try {
    const r = await get(url);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    baseline = await r.text();
    const { verdict, doc } = verifyRaw(baseline);
    // round-53 (UST-ybn): a NON-genesis name-form doc now verifies INDETERMINATE (not name-bound), so the class gate must
    // precede the validity gate — otherwise a served observation is rejected with the vague "does not VERIFY" instead of the
    // precise "not a genesis". A genesis is name-form by design (exempt from the name-claim rule) and verifies normally.
    if (doc && doc.state?.id?.class !== 'genesis') throw new Error(`well-known serves class:${doc.state?.id?.class ?? '?'} — not a genesis`);
    if (!P.isValid(verdict)) throw new Error('published document does not VERIFY' + (verdict.error ? ` (${verdict.error})` : ''));
    if (doc.state?.id?.domain_shard !== domain) throw new Error(`genesis domain_shard is ${doc.state?.id?.domain_shard ?? '?'} — not ${domain}`);
    hash = P.contentHash(doc);
    genesisCadence = doc.state?.data?.genesis?.value?.cadence ?? null;
    if (expectHash && hash !== expectHash) throw new Error(`content_hash differs from --expect (${hash} ≠ ${expectHash})`);
    checks.push({ id: 'well-known verifies (§14, fail-closed)', status: 'pass', detail: hash });
  } catch (e) {
    checks.push({ id: 'well-known verifies (§14, fail-closed)', status: 'fail', detail: e.message });
    return { hash: null, checks, verdict: verdictOf(checks) }; // nothing downstream is meaningful without (1)
  }

  // (1b) key log: when served, it must be the ARRAY shape, every entry verifying and CHAINED to this
  // genesis; absent = NOT ATTESTED (the HIGH path needs it). Never silently untested again.
  let keylogEntries = [];
  try {
    const kr = await get(`https://${domain}/.well-known/ust-keylog`);
    if (!kr.ok) checks.push({ id: 'key log served (HIGH resolution input)', status: 'skip', detail: `HTTP ${kr.status} — not served; verifiers cannot resolve HIGH from the well-known alone` });
    else {
      const parsed = parseKeylogRaw(await kr.text());
      if (parsed.err) throw new Error(parsed.err);
      const chainErr = validateKeylogChain(decodeInput(baseline), parsed.entries);
      if (chainErr) throw new Error(chainErr);
      keylogEntries = parsed.entries;
      checks.push({ id: 'key log served (HIGH resolution input)', status: 'pass', detail: `${parsed.entries.length} entr${parsed.entries.length === 1 ? 'y' : 'ies'}, chained to this genesis` });
      // §12.2/#106 — an operator must see what a CONSUMER sees. A role is read from the served log by anyone
      // resolving a key, so an operator that cannot see it here is the only party in the dark about its own
      // separation. Reported from `resolveKeys`, never re-derived from the entries by a second reader.
      // INFORMATIONAL by construction (F.4 rev92): §20.1 attests the SERVING contract — is the identity fetchable,
      // byte-stable, independently mirrored. Role separation is a property of the key log's CONTENT, a different
      // axis, so scoring it here would make a publisher that deliberately declares no roles permanently
      // non-conformant on a contract it fully meets. The scored set stays closed under the axis it names; the
      // reported set is allowed to be wider, and this is the wider part.
      const ks = P.resolveKeys(decodeInput(baseline), parsed.entries);
      if (ks.error) checks.push({ id: 'key roles (§12.2)', informational: true, status: 'fail', detail: `${ks.error}: ${ks.detail || ''}` });
      else if (!ks.declaredRoles) checks.push({ id: 'key roles (§12.2)', informational: true, status: 'skip', detail: 'this genesis declares no role separation — every key signs everything, and a leak of one signs everything the publisher signs' });
      else {
        const shown = [...ks.active.keys()].map((kid) => `${(ks.roles.get(kid) ?? '(none)')}:${kid.slice(7, 15)}`).join(' · ');
        checks.push({ id: 'key roles (§12.2)', informational: true, status: 'pass', detail: `declared ${[...ks.declaredRoles].join('/')} — active: ${shown}` });
      }
    }
  } catch (e) {
    checks.push({ id: 'key log served (HIGH resolution input)', status: 'fail', detail: e.message });
  }

  // (1c) cadence log — the §11.3 grid. ABSENT is NOT a defect and must never read as one: it is a positive
  // fact about this publisher, that a range verdict over its stream can reach `chain-consistent` (no deletion)
  // and never `complete` (no omission), because nothing signed says how many slots SHOULD be there. UNREADABLE
  // is a different fact and fails, for the same reason `ust cadence` refuses it: an unreadable log is not an
  // empty one, and treating it as empty manufactures a completeness verdict out of a transport failure.
  try {
    const cr = await get(`https://${domain}/.well-known/ust-cadence`);
    if (cr.status === 404 || cr.status === 410) {
      checks.push(genesisCadence
        // §11.3: `genesis.value.cadence` is the INITIAL value and the log is OPTIONAL. Reading only the log told a
        // publisher whose genesis declares a grid that its streams "can never reach complete" — false, and false in
        // the direction that matters: it describes a capability the publisher HAS as one it lacks.
        ? { id: 'cadence declared (completeness input)', informational: true, status: 'pass', detail: `${genesisCadence}s — declared IN THE GENESIS (§11.3 initial value); no log served, which is optional` }
        : { id: 'cadence declared (completeness input)', informational: true, status: 'skip', detail: `HTTP ${cr.status} — no signed grid anywhere: not in the genesis value, no log served. Streams stay chain-consistent and can never reach complete` });
    } else if (!cr.ok) throw new Error(`HTTP ${cr.status} — served but UNREADABLE (an unreadable log is not an empty one)`);
    else {
      const log = JSON.parse(await cr.text());
      if (!Array.isArray(log)) throw new Error('the served cadence log is not a JSON array');
      // resolved AT NOW: the grid is time-relative, so "what is in force" is only answerable at a moment.
      const iso = new Date().toISOString();
      const r = P.resolveCadence(verifyRaw(baseline).doc, log, `ust:${iso.slice(0, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}.${iso.slice(11, 13)}`, { keylog: keylogEntries });
      if (r.error) throw new Error(`${r.error}${r.detail ? ' — ' + r.detail : ''}`);
      const n = `${log.length} entr${log.length === 1 ? 'y' : 'ies'}`;
      checks.push({ id: 'cadence declared (completeness input)', informational: true, status: 'pass', detail: r.cadence === null ? `${n}, none in force yet (all effective in the future)` : `${r.cadence}s in force (${n})` });
    }
  } catch (e) {
    checks.push({ id: 'cadence declared (completeness input)', informational: true, status: 'fail', detail: e.message });
  }

  // (1d) witness — the no-fork evidence surface, and the ONE discovery artifact that had no probe (#91). Its
  // absence is benign: a publisher may assert no-fork by other means, and the LIGHT floor never depended on it.
  // What is NOT benign is a witness that SHRINKS: on 2026-07-27 every deploy rebuilt the log from the genesis and
  // dropped its Rekor/OTS anchors, the git mirror's append-only guard refused the shrink silently, and the loss
  // sat unreported for two weeks on every public surface. So the detail carries the ANCHOR COUNT — a number that
  // falling from 2 to 0 is exactly what a comparison between two attestations must be able to see.
  try {
    const wr = await get(`https://${domain}/.well-known/ust-witness`);
    if (wr.status === 404 || wr.status === 410) {
      // F.5p: absence is TWO facts and the CORE decides which one this is, from (declared, observed).
      const wv = P.surfaceVerdict({ surface: 'witness', declared: declaredSurfaces.has('witness'), observed: 'absent' });
      checks.push({ id: 'witness served (no-fork evidence)', informational: wv.status !== 'failed', status: wv.status === 'failed' ? 'fail' : 'skip',
        detail: wv.status === 'failed'
          ? `HTTP ${wr.status} — the §20 profile DECLARES a witness surface and it did not answer: a promise not kept, not a missing option`
          : `HTTP ${wr.status} — NOT OFFERED: no witness surface, and the profile declares none` });
    } else if (!wr.ok) throw new Error(`HTTP ${wr.status} — served but UNREADABLE (an unreadable witness is not an absent one)`);
    else {
      const w = JSON.parse(await wr.text());
      if (w?.domain_shard !== domain) throw new Error(`witness is for ${w?.domain_shard ?? '?'} — not ${domain}`);
      if (!Array.isArray(w.genesis_log)) throw new Error('witness carries no genesis_log array');
      if (w.active !== hash) throw new Error(`witness \`active\` is ${String(w.active).slice(0, 22)}… — not the served genesis`);
      const entry = w.genesis_log.find((e) => e.content_hash === hash);
      if (!entry) throw new Error('the served genesis is absent from the witness genesis_log');
      const anchors = Array.isArray(entry.anchors) ? entry.anchors.length : 0;
      checks.push({ id: 'witness served (no-fork evidence)', informational: true, status: 'pass',
        detail: `${w.genesis_log.length} genesis entr${w.genesis_log.length === 1 ? 'y' : 'ies'}, active matches, ${anchors} anchor${anchors === 1 ? '' : 's'}` });
    }
  } catch (e) {
    checks.push({ id: 'witness served (no-fork evidence)', informational: true, status: 'fail', detail: e.message });
  }

  // (2) DNS pair: _ust TXT must carry THIS hash — and NO CONFLICTING binding may exist (line-review:
  // one matching record among conflicting ones previously passed; a forked/stale DNS state must surface)
  try {
    const doh = await get(`https://cloudflare-dns.com/dns-query?name=_ust.${domain}&type=TXT`, { headers: { accept: 'application/dns-json' } }).then((r) => r.json());
    const txts = (doh.Answer || []).map((a) => (a.data || '').replace(/"/g, ''));
    const ours = txts.filter((t) => t.startsWith('ust-genesis='));
    const conflicting = ours.filter((t) => t !== 'ust-genesis=' + hash);
    if (!ours.length) checks.push({ id: 'DNS record (_ust TXT) matches', status: 'skip', detail: 'no _ust TXT found — pair NOT ATTESTED (publish ust-genesis=<content_hash>)' });
    else if (conflicting.length) checks.push({ id: 'DNS record (_ust TXT) matches', status: 'fail', detail: `CONFLICTING binding${conflicting.length > 1 ? 's' : ''} present (${conflicting[0]}) — exactly one active ust-genesis binding is required` });
    else checks.push({ id: 'DNS record (_ust TXT) matches', status: 'pass', detail: '_ust.' + domain });
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

  // (0') the §20 OPERATOR PROFILE — normative since rc.1 and, until this round, fetched by nothing. It is what
  // separates the two facts hiding behind one `absent`: a surface this operator does not run (settled) from one
  // that exists and did not answer (a promise not kept). Absent profile = declares nothing, which is the honest
  // floor: every optional surface then reports NOT OFFERED rather than FAILED, and a PRESENT one still attests.
  let declaredSurfaces = new Set();
  try {
    const pr = await get(`https://${domain}/.well-known/ust`);
    if (pr.ok) {
      const prof = JSON.parse(await pr.text());
      const list = Array.isArray(prof?.serves) ? prof.serves.filter((x) => typeof x === 'string') : [];
      declaredSurfaces = new Set(list);
      checks.push({ id: 'operator profile (§20)', informational: true, status: 'pass', detail: list.length ? `declares: ${list.join(', ')}` : 'served, declares no optional surface' });
    } else if (pr.status === 404 || pr.status === 410) {
      checks.push({ id: 'operator profile (§20)', informational: true, status: 'skip', detail: `HTTP ${pr.status} — no profile, so nothing is DECLARED and every optional surface reports NOT OFFERED rather than failing` });
    } else throw new Error(`HTTP ${pr.status} — served but UNREADABLE (an unreadable profile is not an absent one)`);
  } catch (e) {
    checks.push({ id: 'operator profile (§20)', informational: true, status: 'fail', detail: e.message });
  }

  // (4) BYTE-AGREEMENT across declared copies: every named copy must carry the SAME content_hash (bytes are
  // content-addressed — the copy is untrusted, the hash decides). None declared = NOT ATTESTED, never a pass.
  //
  // This leg is NOT vendor-independence and this tool must never call it that (§20.1, formal model F.5o).
  // Fetching two URLs and comparing hashes is decidable from the bytes; whether those URLs sit in different
  // failure domains is NOT — two hostnames on one provider, one account, one region produce an observation
  // identical to two genuinely separate vendors. Naming the leg after the property it cannot decide would let
  // whoever supplies the list grant the property by choosing it, which is the self-declaration F.5a.1 excludes
  // on the witness axis. Independence enters from consumer configuration or external evidence, never from here.
  if (!mirrors.length) checks.push({ id: 'byte-agreement across declared copies (≥1 copy)', status: 'skip', detail: 'no --mirror declared — property NOT ATTESTED' });
  const fetched = [];
  for (const m of mirrors) {
    try {
      const t = await get(m).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`))));
      const { verdict: mv, doc: d } = verifyRaw(t);
      if (!P.isValid(mv)) throw new Error('copy does not VERIFY' + (mv.error ? ` (${mv.error})` : ''));
      fetched.push({ locator: m, hash: P.contentHash(d) });
    } catch (e) {
      checks.push({ id: 'copy ' + m, status: 'fail', detail: e.message });
    }
  }
  // the VERDICT is the core's, never this tool's: `replicationAgreement` decides byte-agreement and has no
  // independence coordinate to report, so there is nothing here to overstate (#102, F.5o).
  if (fetched.length) {
    const rep = P.replicationAgreement({ expected: hash, copies: fetched });
    for (const l of rep.agreed) checks.push({ id: 'copy ' + l, status: 'pass', detail: 'content_hash matches' });
    for (const l of rep.disagreed) checks.push({ id: 'copy ' + l, status: 'fail', detail: 'copy carries a DIFFERENT genesis (content_hash differs)' });
  }
  return { hash, checks, verdict: verdictOf(checks) };
}

// Verdict discipline (status honesty): ATTESTED only when everything ran AND passed; skips make it PARTIAL —
// a claim of §20.1 conformance is never granted on unchecked properties.
//
// INFORMATIONAL checks are reported but never scored, and the distinction is an AXIS one rather than a matter of
// severity. §20.1 is the SERVING contract; the cadence grid is §11.3, an input to a COMPLETENESS verdict over a
// stream. A publisher that deliberately declares no grid is fully §20.1-conformant — its streams simply stay
// `chain-consistent` and never reach `complete`. Scoring cadence here would make ATTESTED unreachable for every
// such publisher and would fuse a stream property into a serving verdict. It still SHOWS, and it still prints its
// next command: the map an operator reads is wider than the contract they are graded on.
export function verdictOf(checks) {
  const scored = checks.filter((c) => !c.informational);
  const fail = scored.filter((c) => c.status === 'fail').length;
  const skip = scored.filter((c) => c.status === 'skip').length;
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
  throw new Error(`could not confirm the published well-known after ${attempts} attempts (~${Math.round(attempts * delayMs / 60000)} min): ${last.message}\n  authoritative NOT granted. DNS/proxy propagation can take a few minutes — your artifacts are ALREADY written and the deployment may be fine; verify later with:  ${invocation()} discovery ${domain} --expect ${genHash}`);
}

// The closing picture: WHAT exists now, WHO holds which key, WHERE you are on the tier ladder, and the
// exact next moves. Exported so the regression suite pins custody classes and the no-overclaim wording.
// RFC 2606 / RFC 6761 names that cannot exist on the internet. The only place a scripted ceremony is allowed:
// there is nothing behind such a name to compromise, so a harness can drive a full ceremony without creating a door
// on a real one. Kept next to the summary so the list and its reason travel together.
export const RESERVED_TEST_NAME = /(\.(test|example|invalid|localhost)|^(www\.)?example\.(com|net|org))$/i;

// THE ARTIFACT MUST STATE WHAT IT IS NOT. A genesis that omits `recovery` or `checkpoint_authority` verifies
// perfectly and is quietly missing a capability that can NEVER be added without minting a new one. That is the
// dangerous shape for an operator who does not know the mechanics: nothing is broken, nothing warns, and the loss
// only surfaces on the day it is needed. Measured 2026-07-28: the reference operator completed a ceremony in exactly
// that state and had no way to know. So the summary now says, in plain words, what this identity cannot do.
function ceremonyLimits({ cadence, recovery, checkpointAuthority }) {
  const out = [];
  if (!recovery) out.push(
    '  ⚠️  NO RECOVERY SET — if the cold backup or its passphrase is lost, or the root key is compromised,',
    '      there is no way back to THIS name: you would start a new identity and consumers would follow a new',
    '      hash. With a recovery set, a threshold of spare keys can re-root the name instead.');
  if (!checkpointAuthority) out.push(
    '  ⚠️  NO CHECKPOINT AUTHORITY — every verifier reads your ENTIRE key history on every check. Fine today,',
    '      slower and heavier as rotations accumulate. A checkpoint authority lets a verifier trust a signed',
    '      summary instead of walking the log.');
  if (!cadence) out.push(
    '  ⚠️  NO CADENCE — a range of your frames can never verify as `complete`, only as `chain-consistent`',
    '      (nothing was deleted). Honest, and the right choice for a deliberately lossy tier — but it cannot',
    '      be upgraded later.');
  if (!out.length) return [];
  return ['', '  🚧 what this identity CANNOT do — and these three are settable at CEREMONY TIME ONLY:', ...out,
    '      Changing any of them means minting a NEW genesis (a supersession) and moving your consumers to it.', ''];
}

// The handoff out of an air-gapped ceremony. Two lists, and the split between them is the whole point: the PUBLIC
// documents travel and are published; the KEYS stay, and one of them never leaves that machine at all. Printed by the
// tool rather than kept in a runbook, because a runbook drifts from the code and this cannot.
export function offlineHandoff({ domain, outDir, genHash }) {
  return [
    '',
    '  ══════════════════════════════════════════════',
    '  ✈️  OFFLINE HALF COMPLETE — nothing was sent anywhere',
    '  ══════════════════════════════════════════════',
    `  identity      ${genHash}`,
    '',
    '  📤 CARRY OUT — public, safe to copy anywhere:',
    `     ${outDir}/ust-genesis`,
    `     ${outDir}/ust-keylog-0`,
    '',
    '  🔥 CARRY OUT — a SECRET, but it must reach your producer:',
    `     ${outDir}/operational-key.b64      → the daily signer. Into your producer's secret store,`,
    '                                          then DELETE the file. Never into git.',
    '',
    '  🧊 DO NOT CARRY OUT — these stay on this machine or go to cold storage BY HAND:',
    `     ${outDir}/genesis-key*.b64          → the crown. If it reaches a networked machine, the`,
    '                                          air gap you just kept is spent.',
    '     recovery-key-*.b64                 → split them across places; a threshold whose keys',
    '                                          share one directory is a threshold of one.',
    '     checkpoint-authority-key.b64       → cold, like the crown.',
    '',
    '  ▶️  THE ONLINE HALF — on a networked machine, with ONLY the two public documents:',
    `     ${invocation()} publish cf --domain ${domain} --genesis ./ust-genesis`,
    '     (the key log rides along: ust-keylog-0 is found next to the genesis)',
    '',
    '     It fetches whatever witness log is live and builds the SUCCESSOR from it: your predecessor',
    '     keeps its anchors and is marked superseded, this identity becomes active. If nothing is live,',
    '     it is a first log. Either way the crown key is not involved and is not needed.',
    '',
    '  ✅ then verify from anywhere, trusting nobody:',
    `     ${invocation()} verify ./ust-genesis --genesis ./ust-genesis --keylog ./ust-keylog-0`,
    `     ${invocation()} discovery ${domain}`,
    '  ══════════════════════════════════════════════',
  ];
}

export function ceremonySummary({ domain, genHash, opKeyId, maxP, cadence, outDir, encrypted, recovery = null, checkpointAuthority = null }) {
  return [
    '',
    '  ══════════════════════════════════════════════',
    `  ✅ GENESIS CEREMONY COMPLETE — ${domain}`,
    '  ══════════════════════════════════════════════',
    `  identity      ${genHash}`,
    `  operational   ${opKeyId}  (warm daily signer)`,
    `  capacity      max_partitions ${maxP ?? '(floor 64)'}`,
    '  cadence       ' + (cadence ? cadence + 's  (streams can reach complete; a lossy tier stays chain-consistent)' : '(none — completeness stays chain-consistent)'),
    '',
    '  📦 files & custody',
    `  ${outDir}/ust-genesis + ust-keylog-0    → PUBLIC — anyone can \`ust verify\` them`,
    `  ${outDir}/genesis-key${encrypted ? '.enc' : ''}.b64${encrypted ? '' : '        '}          → 🧊 COLD — the crown backup; keep the file and its passphrase APART`,
    `  ${outDir}/operational-key.b64           → 🔥 WARM — your producer's signing-key secret, then DELETE this file`,
    '',
    ...ceremonyLimits({ cadence, recovery, checkpointAuthority }),
    '  🎚  tier ladder — where you are',
    '  LIGHT  ✅ now   — each document verifies self-asserted: signed + intact under its carried key',
    '  HIGH   ⏳ next  — a verifier RESOLVES genesis→key-log (+ no-fork witness) and your NAME becomes',
    `                   authoritative:  ${invocation()} verify <doc> --genesis ust-genesis --keylog ust-keylog-0 --no-fork-confirmed`,
    '  TOP    ⏳ later — anchored TIME for each document (e.g. bitcoin-ots). Stream COMPLETENESS is a',
    `                   SEPARATE range verdict:  ${invocation()} stream <frames…> --checkpoint <cp>`,
    '',
    '  ➡️  next moves',
    "  1. operational-key.b64 → your producer's signing-key secret (an env var of YOUR naming), then DELETE the file",
    '  2. revoke the ceremony credentials (wrangler logout + the DNS token)',
    `  3. re-attest the serving contract anytime:  ${invocation()} discovery ${domain}`,
    '  4. HIGH: run the witness exchange + serve the key log    5. TOP: queue the anchor',
    '  ══════════════════════════════════════════════',
  ];
}

// ─── the MIRROR method — publish a SECOND copy and attest that it AGREES (owner: a general CLI method —
// and never trust the user's word that the bytes are there; ATTEST by fetching). The roads mirror the
// serving adapter: by-hand anywhere + a gh one-click (delegate to the vendor's own authenticated CLI,
// exactly like wrangler for CF).
//
// The earlier version of this comment read "a mirror is BY DEFINITION on a second vendor" — an ASSUMPTION
// standing where a check belongs. Putting the copy somewhere separate is the operator's duty (§20.1) and a
// good reason to run this command; what the command can PROVE is only that the copies agree byte for byte.

// Fetch the CANONICAL surfaces (hash-verified) and attest every mirror URL against them — the mirror is
// untrusted by design: bytes are fetched, verified as UST, and content_hash-matched. Never a claim.
export async function attestMirror({ domain, genesisUrls = [], keylogUrls = [], fetchImpl = fetch }) {
  const get = (u) => fetchImpl(u, { signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`))));
  const canonical = await get(`https://${domain}/.well-known/ust-genesis`);
  const { verdict: cv, doc: canonDoc } = verifyRaw(canonical);
  if (!P.isValid(cv)) throw new Error('the canonical well-known does not VERIFY — fix serving before mirroring' + (cv.error ? ` (${cv.error})` : ''));
  if (canonDoc.state?.id?.class !== 'genesis' || canonDoc.state?.id?.domain_shard !== domain) throw new Error('the canonical well-known is not this domain\'s genesis — fix serving before mirroring');
  const canonHash = P.contentHash(canonDoc);
  let canonKeylogHashes = null; // entry hashes when the canonical key log is served
  try {
    const klParsed = parseKeylogRaw(await get(`https://${domain}/.well-known/ust-keylog`));
    if (!klParsed.err) canonKeylogHashes = klParsed.entries.map((e) => P.contentHash(e));
  } catch { /* canonical key log not served (yet) — keylog mirrors will be reported unverifiable */ }

  const results = [];
  for (const url of genesisUrls) {
    try {
      const { verdict: gv, doc: d } = verifyRaw(await get(url));
      if (!P.isValid(gv)) throw new Error('mirror document does not VERIFY' + (gv.error ? ` (${gv.error})` : ''));
      if (P.contentHash(d) !== canonHash) throw new Error('mirror carries a DIFFERENT genesis (content_hash differs)');
      results.push({ kind: 'genesis', url, status: 'pass', detail: 'content_hash matches the canonical' });
    } catch (e) { results.push({ kind: 'genesis', url, status: 'fail', detail: e.message }); }
  }
  for (const url of keylogUrls) {
    try {
      if (!canonKeylogHashes) { results.push({ kind: 'keylog', url, status: 'skip', detail: 'canonical /.well-known/ust-keylog is not served — nothing to match against' }); continue; }
      const parsed = parseKeylogRaw(await get(url));
      if (parsed.err) throw new Error(parsed.err);
      const hashes = parsed.entries.map((e) => P.contentHash(e));
      if (JSON.stringify(hashes) !== JSON.stringify(canonKeylogHashes)) throw new Error('mirror key log DIFFERS from the canonical (entry hashes differ)');
      results.push({ kind: 'keylog', url, status: 'pass', detail: `${parsed.entries.length} entr${parsed.entries.length === 1 ? 'y' : 'ies'}, hashes match` });
    } catch (e) { results.push({ kind: 'keylog', url, status: 'fail', detail: e.message }); }
  }
  return { canonHash, results, failed: results.some((r) => r.status === 'fail') };
}

// GitHub one-click: publish the mirror bytes into a PUBLIC repo via the user's own authenticated `gh`
// CLI (same delegation pattern as wrangler — we never hold the credential). Idempotent: create-or-update
// by sha. Returns the raw URLs a verifier fetches.
export // A mirror carries the WHOLE identity or it lies about the part it carries. Publishing genesis+keylog while leaving
// a stale witness behind produced the worst state of the three: a consumer reads a genesis that the mirror's OWN
// witness says is not active. Measured after a supersession — the same one-of-four defect retired from the operator's
// archiver this morning, still living here.
//
// And an artifact the domain STOPPED serving must be REMOVED, not left: after a supersession the old cadence log is
// rooted in the superseded genesis, so mirroring it would attest a document that belongs to a name that no longer
// resolves. Absent upstream ⇒ absent here.
async function ghMirrorPublish({ repo, dir = 'mirror', artifacts = {}, execImpl = null }) {
  const exec = execImpl ?? (async (args) => {
    const { spawnSync } = await import('node:child_process');
    const r = spawnSync('gh', args, { encoding: 'utf8' });
    if (r.status !== 0) throw new Error('gh failed: ' + (r.stderr || r.stdout || 'not logged in? run `gh auth login`').trim().slice(0, 200));
    return r.stdout;
  });
  const branch = (await exec(['api', `repos/${repo}`, '--jq', '.default_branch'])).trim() || 'main';
  const putFile = async (name, content) => {
    let sha = null;
    try { sha = (await exec(['api', `repos/${repo}/contents/${dir}/${name}?ref=${branch}`, '--jq', '.sha'])).trim() || null; } catch { sha = null; }
    const args = ['api', '-X', 'PUT', `repos/${repo}/contents/${dir}/${name}`,
      '-f', `message=ust mirror: ${name}`, '-f', `content=${Buffer.from(content).toString('base64')}`, '-f', `branch=${branch}`];
    if (sha) args.push('-f', `sha=${sha}`);
    await exec(args);
    return `https://raw.githubusercontent.com/${repo}/${branch}/${dir}/${name}`;
  };
  // an artifact the domain stopped serving is DELETED from the mirror — leaving it would attest a document
  // belonging to a superseded identity, which is worse than not mirroring it at all
  const delFile = async (name) => {
    let sha = null;
    try { sha = (await exec(['api', `repos/${repo}/contents/${dir}/${name}?ref=${branch}`, '--jq', '.sha'])).trim() || null; } catch { return false; }
    if (!sha) return false;
    await exec(['api', '-X', 'DELETE', `repos/${repo}/contents/${dir}/${name}`,
      '-f', `message=ust mirror: ${name} no longer served upstream`, '-f', `sha=${sha}`, '-f', `branch=${branch}`]);
    return true;
  };
  const urls = {}, removed = [];
  for (const name of DISCOVERY_ARTIFACTS) {
    const text = artifacts[name];
    if (text == null) { if (await delFile(`ust-${name}`)) removed.push(name); continue; }
    urls[name] = await putFile(`ust-${name}`, text);
  }
  return { urls, removed, branch, genesisUrl: urls.genesis ?? null, keylogUrl: urls.keylog ?? null };
}

// The closing story every publishing flow must end with (owner: "я вообще не понимаю что мне дальше
// делать и где мой HIGH") — what just happened, the explicit PATH TO HIGH for the publisher's own
// documents, and the housekeeping. One source, printed by publish AND folded into the ceremony summary.
// The ladder reports what was MEASURED where it can. Step 3 was a hardcoded ⬜ printed directly beneath a §20.1
// run that had just confirmed the key log IS served — the operator was shown a step to do and the evidence it was
// already done, in the same screen. A checklist that does not read its own measurements is decoration.
export function whatsNextSummary({ domain, genHash, checks = [] }) {
  const passed = (idPrefix) => checks.some((c) => c.id?.startsWith(idPrefix) && c.status === 'pass');
  const keylogServed = passed('key log served');
  return [
    '',
    '  ─── what just happened ───',
    '  ✅ your name has a LIVE, verifiable identity:',
    `     the genesis (${genHash.slice(0, 20)}…) is served at https://${domain}/.well-known/ust-genesis`,
    '     and pinned in DNS (_ust TXT). Anyone in the world can verify it.',
    '',
    '  ─── the path to HIGH for YOUR documents ───',
    '  ✅ 1. identity live — genesis + key-log minted, serving attested',
    '  ⬜ 2. your producer signs with the operational key',
    '        load operational-key.b64 as its signing-key secret, then DELETE the file',
    `  ${keylogServed ? '✅' : '⬜'} 3. key log resolvable — ${keylogServed ? 'served and chained to this genesis (attested above)' : 'the cf adapter serves it at /.well-known/ust-keylog;'}`,
    ...(keylogServed ? [] : ['        by hand: publish ust-keylog-0 yourself (a verifier needs BOTH to resolve your name)']),
    '  ⬜ 4. verifiers resolve — YOUR documents then verify HIGH:',
    `        ${invocation()} verify <doc> --genesis ust-genesis --keylog ust-keylog-0 --no-fork-confirmed`,
    '  ⏳ later: witness exchange (backs the no-fork assertion) · anchor the stream → TOP',
    '',
    '  ─── housekeeping (do these NOW) ───',
    '  · revoke the ceremony credentials:  npx wrangler logout  + delete the DNS token in the dashboard',
    '  · genesis-key(.enc).b64 → cold storage; the passphrase lives APART from the file',
    `  · re-attest the serving contract anytime:  ${invocation()} discovery ${domain}`,
  ];
}

// REMINT probe (line-review P1: the guard was fail-open — timeout/garbage/TLS-error all proceeded to
// mint). Three-state, fail-closed: 'absent' ONLY on a proven 404/410; a valid genesis for THIS domain =
// 'live'; EVERYTHING else (network error, non-UST bytes, foreign/wrong-class document) = 'indeterminate'
// — and an operation able to orphan an identity stops on indeterminate unless explicitly overridden.
export async function remintProbe({ domain, fetchImpl = fetch }) {
  let res;
  try { res = await fetchImpl(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(8000) }); }
  catch (e) { return { status: 'indeterminate', detail: 'well-known unreachable: ' + e.message }; }
  if (res.status === 404 || res.status === 410) return { status: 'absent', detail: `HTTP ${res.status}` };
  if (!res.ok) return { status: 'indeterminate', detail: `HTTP ${res.status} — neither a proven absence nor a readable identity` };
  let text; try { text = await res.text(); } catch (e) { return { status: 'indeterminate', detail: 'body unreadable: ' + e.message }; }
  try {
    const { verdict, doc } = verifyRaw(text);
    if (P.isValid(verdict) && doc.state?.id?.class === 'genesis' && doc.state?.id?.domain_shard === domain)
      return { status: 'live', hash: P.contentHash(doc), detail: 'a verifiable genesis for ' + domain };
    return { status: 'indeterminate', detail: 'the well-known serves bytes that are NOT this domain\'s genesis' };
  } catch { return { status: 'indeterminate', detail: 'the well-known serves non-UST bytes' }; }
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
  if (!src) die('usage: ust verify <file | - for stdin> [--context data|key] [--offline] [--genesis <file> --keylog <file[,file…]> [--no-fork-confirmed | --witness <file> --trust-root KEYID=PUB[,…]]] [--require-authoritative] [--require-anchored]\n  by default the tool AUTO-RESOLVES the publisher identity from its /.well-known/ discovery pair\n  --no-fork-confirmed = YOUR air-gap assertion ⇒ consumer-override (not authoritative) · --witness <buildNoForkEvidence JSON> + --trust-root (witness pubkeys YOU trust) ⇒ INDEPENDENT authoritative\n  --require-authoritative floors at HIGH · --require-anchored floors at TOP (downgrade resistance: below-floor ⇒ reject, never a silent lower tier)\n  --require-fresh-keylog rejects a possibly-stale key-log (§12.2a) · --keylog-fresh-as-of <RFC3339-Z> supplies fresh-fetch evidence (attested needs a verified head-anchor proof, API-only)');
  const raw = src === '-' ? readFileSync(0) : readFileSync(src);   // Buffer — admission precedes decode
  // pre-parse ONLY to pick the context — the VERDICT below comes from the normative raw path
  let doc; try { doc = decodeInput(raw.toString('utf8')); } catch (e) { die('not a UST blob/base64/json: ' + e.message); }

  // optional HIGH resolution: every input passes the RAW boundary; the capacity grant flows FROM
  // authority resolution (rc.12), never a raw caller-attached genesis. The verifier's OWN resource
  // envelope (ρ_v) is expressible: --max-input-bytes (transport) / --max-supported-bytes (capability).
  let opts = { context: arg('context', null) || contextFor(doc) };
  for (const [flag, key] of [['max-input-bytes', 'maxInputBytes'], ['max-supported-bytes', 'maxSupportedBytes']]) {
    const v = arg(flag, null);
    if (v === true) die(`--${flag} needs a value`);
    if (v !== null) opts[key] = Number(v);
  }
  // selective disclosure (F.7a): local nonce/value map + decryption keys widen what the verifier can check
  for (const [flag, key] of [['disclosures', 'disclosures'], ['dec-keys', 'decKeys']]) {
    const v = arg(flag, null);
    if (v === true) die(`--${flag} needs a value (a JSON file)`);
    if (v !== null) { try { opts[key] = JSON.parse(readFileSync(v, 'utf8')); } catch (e) { die(`could not read --${flag} ${v}: ` + e.message); } }
  }
  // §3.1/F.5b downgrade-resistance FLOORS — a consumer requiring tier T rejects anything below it (never a silent
  // lower-tier accept). requireAuthoritative floors at HIGH, requireAnchored at TOP.
  if (arg('require-authoritative', false)) opts.requireAuthoritative = true;
  if (arg('require-anchored', false)) opts.requireAnchored = true;
  // §12.2a #40 key-log freshness — floor + evidence inputs (a stale cache can accept a revoked key silently).
  if (arg('require-fresh-keylog', false)) opts.requireFreshKeylog = true;
  { const f = arg('keylog-fresh-as-of', null); if (f && f !== true) opts.keylogFreshAsOf = f; }
  const genesisPath = arg('genesis', null);
  const noFork = !!arg('no-fork-confirmed', false);
  if (genesisPath && genesisPath !== true) {
    let genesisDoc, keylogDocs;
    try {
      const g = verifyRaw(readFileSync(genesisPath, 'utf8'));
      if (!P.isValid(g.verdict)) die('the --genesis file does not VERIFY (' + (g.verdict.error ?? g.verdict.result) + ')');
      genesisDoc = g.doc;
      const kl = arg('keylog', null);
      keylogDocs = (kl && kl !== true ? String(kl).split(",") : []).flatMap((pth) => {
        const t = readFileSync(pth, "utf8");
        const asArr = parseKeylogRaw(t);
        if (!asArr.err) return asArr.entries;
        const single = verifyRaw(t, { context: 'key' });
        if (!P.isValid(single.verdict)) die('the --keylog file ' + pth + ' does not VERIFY (' + (single.verdict.error ?? single.verdict.result) + ')');
        return [single.doc];
      });
    } catch (e) { die('could not read the resolution inputs: ' + e.message); }
    // UST-3dj — witness no-fork EVIDENCE + consumer TRUST ROOTS reach the INDEPENDENT authoritative rung
    // (a bare --no-fork-confirmed is only a consumer-override). --witness <file> = a buildNoForkEvidence JSON;
    // --trust-root KEYID=PUB[,KEYID=PUB…] = the witness/authority pubkeys the CONSUMER trusts (consumer-rooted, never the doc).
    let noForkEvidence, trustRoots;
    { const wp = arg('witness', null); if (wp && wp !== true) { try { noForkEvidence = JSON.parse(readFileSync(wp, 'utf8')); } catch (e) { die('could not read --witness evidence: ' + e.message); } } }
    { const tr = arg('trust-root', null); if (tr && tr !== true) { trustRoots = {}; for (const pair of String(tr).split(',')) { const [kid, pub] = pair.split('='); if (!kid || !pub) die('--trust-root must be KEYID=PUB[,KEYID=PUB…]'); trustRoots[kid.trim()] = pub.trim(); } } }
    const auth = P.resolveAuthority(doc, { genesis: genesisDoc, keylog: keylogDocs, noForkConfirmed: noFork, noForkEvidence, trustRoots });
    if (auth.error) die('authority resolution failed: ' + auth.error + (auth.detail ? ' — ' + auth.detail : ''));
    opts = { ...opts, genesis: genesisDoc, keylog: keylogDocs, noForkConfirmed: noFork, noForkEvidence, trustRoots, capacity: auth.capacity };
  }

  let { verdict: r } = verifyRaw(raw, opts);
  // AUTO-RESOLUTION by default (owner: an agent/human receives a HIGH UST and by default sees LIGHT —
  // or, above the floor, nothing at all): the document carries its own name → fetch the §20.1 discovery
  // pair from it, resolve, re-verify with the grant. --offline forbids the network. Honesty holds:
  // HIGH still requires YOUR --no-fork-confirmed — auto-resolution never silently grants authority.
  let resolution = null;
  if (!genesisPath) {
    // the SINGLE resolver (ust-protocol resolveByDiscovery, rc.13) — SSRF guard + one-copy flow live there
    // opt-in Bitcoin cross-check: if @ust-protocol/ots-verify is installed, the witness genesis anchor is
    // verified against Bitcoin (→ live HIGH); if not, the anchor stays unproven (→ honest HIGH pending).
    // opt-in substrate plugins: Bitcoin (ots-verify) + Rekor (rekor-verify), combined via the protocol
    // router. Whichever are installed contribute; none installed → anchor unproven → honest HIGH-pending.
    const plugins = [], incPlugins = [];
    for (const pkg of ['@ust-protocol/ots-verify', '@ust-protocol/rekor-verify']) {
      try { const m = await import(pkg); if (m.substrateVerify) plugins.push(m.substrateVerify); if (m.inclusionVerify) incPlugins.push(m.inclusionVerify); } catch { /* absent */ }
    }
    const substrateVerify = plugins.length ? P.combineSubstrates(plugins) : undefined;
    const inclusionVerify = incPlugins.length ? P.combineInclusion(incPlugins) : undefined;   // #95 — same plugins, other question
    // #71 — the discovery target comes from an UNTRUSTED document; the SSRF guard (resolve → reject private IPs)
    // wraps the fetch on the CLI too, not only the MCP. Core's lexical isPublicDnsShard is the floor beneath it.
    const guardedFetch = makeSsrfSafeFetch(async (u, init) => { console.error(`  ⏳ resolving identity from ${new URL(u).origin} … (--offline to skip)`); return fetch(u, init); });
    const rd = await P.resolveByDiscovery(doc, { context: opts.context, offline: !!arg('offline', false), noForkConfirmed: noFork, requireAuthoritative: opts.requireAuthoritative, requireAnchored: opts.requireAnchored, requireFreshKeylog: opts.requireFreshKeylog, keylogFreshAsOf: opts.keylogFreshAsOf },
      { substrateVerify, fetchImpl: guardedFetch });
    if (!substrateVerify && rd.resolution && String(rd.resolution.noFork || '').startsWith('HIGH pending')) console.error('  ℹ️  anchor not cross-checked — `npm i @ust-protocol/ots-verify @ust-protocol/rekor-verify` for automatic HIGH');
    if (rd.resolution) {
      r = rd.verdict;
      resolution = rd.resolution.skipped ? { error: rd.resolution.skipped }
                 : rd.resolution.error ? { error: rd.resolution.error }
                 : rd.resolution.fork ? { error: rd.resolution.detail }
                 : { publisher: rd.resolution.publisher, capacity: rd.resolution.capacity, noFork: noFork ? 'asserted by you (--no-fork-confirmed)' : rd.resolution.noFork };
    }
  }
  console.log(r.result + (r.error ? '  (' + r.error + (r.detail ? ' — ' + r.detail : '') + ')' : ''));
  if (resolution) {
    if (resolution.error) console.log('  resolve  : ✗ ' + resolution.error);
    else console.log("  resolve  : key ∈ " + resolution.publisher + "'s chain · capacity " + (resolution.capacity?.maxPartitions ?? 'floor') + ' admitted · no-fork ' + resolution.noFork);
  }
  if (P.isValid(r)) {
    const tier = r.result.split(':')[1] ?? 'LIGHT';
    // rev93 third case — a strength is NEVER printed alone. `time` was already printed as `strength/status`
    // one line below; identity was not, so a label the derivation NEUTRALIZED (any strength whose status is not
    // `verified` earns the floor, C3) reached a reader with nothing beside it to say so. A consuming agent reads
    // fields in isolation; a human reads a line in isolation. The pair is the smallest honest unit either can read.
    // rev93 — the strength and its status print as a PAIR (§15). `time` was already printed that way one line
    // below; identity was not, so a label whose status disqualified it reached a reader with nothing beside it to
    // say so. The SEAM label is what prints, deliberately, NOT the earned coordinate: on the `--no-fork-confirmed`
    // path verify() lifts the earned coordinate to `authoritative` while the seam stays `consumer-override`, and
    // that difference IS the provenance an operator must see — that the authority rests on their own assertion.
    console.log('  identity : ' + r.identity.strength + '/' + r.identity.status + ' (mode ' + r.identity.mode + ')  ' + (r.publisher ? 'publisher ' + r.publisher : 'publisher_claimed ' + r.publisher_claimed));
    console.log('  time     : ' + r.time.strength + '/' + r.time.status + '   completeness: ' + r.completeness);
    console.log('  ust_id   : ' + r.ust_id + '   class ' + r.class + '   content_hash ' + r.content_hash);
    if (r.provenance) console.log('  lineage  : declared' + (r.provenance.referents ? `, referents ${r.provenance.referents}` : '') + (r.provenance.depth !== undefined ? ` (walk depth ${r.provenance.depth})` : '') + ' — a declaration is not a verified derivation');
    console.log('  tier     : ' + ['LIGHT', 'HIGH', 'TOP'].map((t) => (t === tier ? `[${t}]` : ` ${t} `)).join('→'));
    if (tier === 'LIGHT' && resolution && !resolution.error && !noFork) {
      console.log('\n  ℹ️  the name RESOLVED (key belongs to its chain, capacity admitted) but stays provisional');
      console.log('     without the no-fork witness. Once you have independently confirmed no rival genesis');
      console.log('     exists, re-run with:  --no-fork-confirmed   → VALID:HIGH');
    } else if (tier === 'LIGHT' && !genesisPath && !resolution) {
      console.log('\n  ✅ this is the EXPECTED result for a lone document — it proves the file is signed and');
      console.log('     intact under the key it carries. HIGH is a property of RESOLUTION, not of the file:');
      console.log('     ${invocation()} verify <doc> --genesis <ust-genesis> --keylog <ust-keylog-0> --no-fork-confirmed');
    } else if (tier === 'LIGHT' && genesisPath && !noFork) {
      console.log('\n  ℹ️  resolution ran but the name is not authoritative WITHOUT the no-fork witness check.');
      console.log('     Once your witness exchange confirms no rival genesis exists, add: --no-fork-confirmed');
    } else if (tier === 'HIGH') {
      console.log('\n  🏛  the NAME is authoritative: genesis→key-log resolved' + (noFork ? ' (+ no-fork asserted by YOU — that assertion is your operator duty)' : ''));
      console.log('     TOP is next: anchored TIME per document. Completeness is a SEPARATE range verdict (ust stream).');
    }
  }
  // three-valued exit contract: absence of information is NOT proven invalidity (F.5)
  process.exit(P.isValid(r) ? 0 : r.result === 'INDETERMINATE' ? 2 : 1);
}

// ─── ust canon <file|-> — the DX diagnostic (#41): print the canonical string + hash so any-language devs diff ─
async function cmdCanon() {
  const src = process.argv[3];
  if (!src) die('usage: ust canon <file | - for stdin>   # prints canonical bytes + hash to diff cross-language');
  const raw = src === '-' ? readFileSync(0, 'utf8') : readFileSync(src, 'utf8');
  const dup = scanDupes(rawTextOf(raw));
  if (dup) die('E-CANON: ' + dup + '  (duplicate members are rejected at the RAW boundary — §6)');
  let v; try { v = JSON.parse(rawTextOf(raw)); } catch (e) { die('not JSON: ' + e.message); }
  // a FULL transcript hashes over canon({ust,state}) — printing the hash of canon(whole doc) as if it
  // were a content_hash mislabels the domain (external review): split the two cases honestly.
  if (v && typeof v === 'object' && v.ust && v.state) {
    let canonical; try { canonical = P.canon({ ust: v.ust, state: v.state }); } catch (e) { die('E-CANON: ' + (e.detail || e.message)); }
    console.log(canonical);
    console.error('# canonical SIGNED CONTENT of a transcript ({ust,state})');
    console.error('# content_hash: ' + P.contentHash(v));
    return;
  }
  let canonical; try { canonical = P.canon(v); } catch (e) { die('E-CANON: ' + (e.detail || e.message) + '  (values must be NFC strings; no numbers/bools/nulls — §5)'); }
  console.log(canonical);
  console.error('# sha256 (generic canonical hash — NOT a content_hash: the input is not a {ust,state} transcript): ' + P.H('ust:state', canonical).slice(7));
}

// ─── ust discovery <domain> — §20.1 compliance attestation (any infra; properties, not mechanisms) ────
// WHICH BUILD SAID THIS (#103). An older checker does not DISAGREE with a newer one — it has nothing to
// say, silently. Measured: the published build printed five checks where the working copy printed seven,
// so `cadence declared` and `witness served` were simply absent, and a reader would have taken the silence
// for a property of the DOMAIN rather than of the instrument. A report that cannot name its own version
// cannot be compared with another report at all.
//
// One function prints the checks AND the stamp, because there are three call sites and a fourth would
// otherwise be free to forget. The version reported is the PROTOCOL's, not the CLI's: the number that
// decides what a check MEANS lives there, and naming a wrapper while the verifier underneath is older
// would be precise about the wrong thing.
const mark = { pass: '✅', fail: '❌', skip: '⬜' };

function printChecks(checks) {
  for (const c of checks) console.log(`  ${mark[c.status]}  ${c.id}${c.detail ? '  (' + c.detail + ')' : ''}`);
  console.log(`\n  checker: ust-protocol ${P.VERSION.spec} (wire ${P.VERSION.wire}, rev ${P.VERSION.revision}) \u00b7 ${checks.length} checks run`);
}

async function cmdDiscovery() {
  const domain = process.argv[3];
  if (!domain || domain.startsWith('--')) die('usage: ust discovery <domain> [--mirror url,url] [--expect sha256:…]   # attest the §20.1 serving contract');
  const mirrors = (arg('mirror', '') || '').split(',').filter(Boolean);
  const expectHash = arg('expect', null);
  const { hash, checks, verdict } = await attestDiscovery({ domain, mirrors, expectHash });
  printChecks(checks);
  console.log(`\n  DISCOVERY CONFORMANCE (§20.1): ${verdict}${hash ? '   genesis ' + hash : ''}   (exit: 0=ATTESTED · 2=PARTIAL · 1=FAILED)`);
  if (verdict === 'PARTIAL') {
    // targeted hints (rc.8): name ONLY what was actually skipped — never advise republishing what already passed
    console.log('  PARTIAL = no violation found, but unchecked properties remain:');
    for (const c of checks.filter((x) => x.status === 'skip')) {
      if (c.id.startsWith('DNS record')) console.log('    → publish the _ust TXT (ust-genesis=<content_hash>) and re-run');
      else if (c.id.startsWith('byte-agreement')) console.log(`    → name a copy to compare bytes against:  ${invocation()} discovery ${domain} --mirror <url>\n      (this attests the copies AGREE; whether they sit on independent vendors is yours to know, not this tool's to attest)`);
      else if (c.id.startsWith('cadence')) console.log(`    → declare the stream grid (a COLD root-key ceremony; needed before a range can read \`complete\`):\n        ${invocation()} cadence --domain ${domain} --root <encrypted-root.b64> --seconds <n> --effective-from <a FUTURE ust_id>`);
      else console.log('    → ' + c.id + ' — ' + c.detail);
    }
  }
  process.exit(verdict === 'FAILED' ? 1 : verdict === 'PARTIAL' ? 2 : 0);
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
  // THE ROAD IS A CHOICE, and it is the same choice the ceremony offers — so it is asked the same way here. It
  // used to be a fatal 'needs CF_TOKEN' with a wall of scope text, which reads as a broken command rather than a
  // fork, and it silently assumed Cloudflare: an operator on their own stack was told about a missing token for a
  // vendor they do not use. The §20.1 contract is vendor-NEUTRAL; the tool now says so where it matters.
  const ROADS = { cf: 'Cloudflare — worker + route + DNS, one command', self: 'your own infrastructure — files written, you serve them' };
  let provider = process.argv[3];
  if (provider && !(provider in ROADS)) die(`unknown road \`${provider}\`. Roads: ` + Object.keys(ROADS).join(' | '));
  if (!provider) {
    if (!process.stdin.isTTY) die('usage: ust publish <cf|self> --domain <d> --genesis <ust-genesis file>\n  cf   — Cloudflare worker + route + DNS\n  self — write the four artifacts and serve them on your own stack');
    console.log('\n  Where does this identity get SERVED? (both roads end at the same §20.1 checks)');
    for (const [k, v] of Object.entries(ROADS)) console.log(`    [${k === 'cf' ? 1 : 2}] ${k.padEnd(5)} ${v}`);
    const rl0 = openReader(createInterface);
    const pick = (await rl0.question('  choose 1 or 2 [2]: ')).trim();
    closeReader(rl0);
    provider = pick === '1' ? 'cf' : 'self';
    console.log(`  → ${provider}\n`);
  }
  const domain = arg('domain'); if (!domain || domain === true) die('--domain is required');
  const genPath = arg('genesis'); if (!genPath || genPath === true) die('--genesis <path to the ust-genesis file> is required');
  const genesisText = readFileSync(genPath, 'utf8');
  const flipProxy = !!arg('flip-proxy', false);
  // the key log rides along by default: --keylog <file>, or ust-keylog-0 found NEXT to the genesis file.
  // A single entry file is wrapped into the served ARRAY shape (a rotation later APPENDS, never rewrites).
  let keylogText = null;
  const klPath = arg('keylog', null) || genPath.replace(/[^/\\]+$/, 'ust-keylog-0');
  try {
    const klRaw = readFileSync(klPath, 'utf8');
    const kl = decodeInput(klRaw);
    keylogText = JSON.stringify(Array.isArray(kl) ? kl : [kl]);
  } catch { if (arg('keylog', null)) die('could not read --keylog ' + klPath); }

  // The cadence log rides along the same way — cadenceText rides along by default: --cadence-log <file>, or an
  // ust-cadence found NEXT to the genesis. Threading it through buildWorkerScript/cfPublish (this morning) gave the
  // artifact a serving PATH; without this the COMMAND never picks the file up, and a deploy would leave
  // /.well-known/ust-cadence a 404 while every gate stayed green — the same seam, one layer out.
  // The witness is the one artifact the publish path SYNTHESISES instead of loading, and synthesising it
  // DESTROYS what it replaces: buildWitnessLog takes anchors as its second argument and this path never passed
  // them, so every deploy overwrote the served log with a minimal one and dropped its Rekor/OTS anchors. The
  // archiver's byte-for-byte git sync then refused the shrink — correctly, and silently — leaving the last intact
  // copy frozen for two weeks with nobody told. So: PRESERVE the served witness. Fetch what is live, keep its
  // anchors, and synthesise only when there is nothing to preserve.
  const served = await collectServed({ domain, genesisText, genPath, keylogText,
    witnessFile: typeof arg('witness', null) === 'string' ? arg('witness', null) : null,
    cadenceFile: typeof arg('cadence-log', null) === 'string' ? arg('cadence-log', null) : null, log: console.log });

  // THE SELF-HOSTED ROAD ends here: the artifacts are assembled exactly as the vendor adapter would assemble them
  // — including the WITNESS, which for a supersession is a successor derived from what is live and cannot be
  // written by hand — and then handed over. Nothing is deployed, no credential is asked for, and the verification
  // is the same `ust discovery` a stranger would run.
  if (provider === 'self') {
    const outDir = typeof arg('out', null) === 'string' ? arg('out', null) : './ust-serve';
    mkdirSync(outDir, { recursive: true });
    const files = { genesis: served.genesisText, keylog: served.keylogText, cadence: served.cadenceText, witness: served.witnessText };
    for (const [name, text] of Object.entries(files)) {
      if (text == null) { console.log(`  ·  ust-${name}: not available — not written, and it will not be served`); continue; }
      writeFileSync(`${outDir}/ust-${name}`, text);
      console.log(`  ✓ wrote ${outDir}/ust-${name}  (${Buffer.byteLength(text)} B)`);
    }
    for (const line of selfHostedPlan({ domain, outDir, genHash: P.contentHash(JSON.parse(served.genesisText)), artifacts: files })) console.log(line);
    return;
  }

  let r;
  if (arg('auth', null) === 'wrangler') {
    // COMBINED flow: worker+route ride wrangler's OAuth (browser login — no workers scopes on any token);
    // the API token shrinks to Zone.DNS:Edit for the apex steps.
    let w; try { w = await wranglerDeploy({ domain, ...served }); } catch (e) { die(e.message); }
    console.log('  ✓ worker ' + w.script + ' deployed via wrangler OAuth (genesis embedded, ' + w.genHash + ')');
    console.log('  ✓ route ' + w.route + ' (from wrangler.toml)');
    const rl = openReader(createInterface);   // lifecycle, not a bare interface: close() alone leaves a live stdin listener on a terminal
    // THE DNS PIN IS PART OF PUBLISHING, not only of the first ceremony. `publish` can change WHICH genesis a
    // domain serves — that is what a supersession is — and it used to leave `_ust` pointing at the old one, so
    // the name stayed bound to a hash the domain no longer served. Measured on a live supersession: the worker
    // carried the new identity while DNS still pinned the predecessor, and §20.1 discovery failed on exactly
    // that conflict. The token asked for here is DNS-scoped; writing the pin is what it is FOR.
    const dnsToken = await resolveDnsToken((q) => rl.question(q));
    let apex, pin;
    try {
      pin = await cfUpsert({ domain, txt: `ust-genesis=${w.genHash}`, genHash: w.genHash, token: dnsToken });
      console.log(`  ✓ _ust.${domain} TXT ${pin.action} → ${w.genHash.slice(0, 26)}…`);
      apex = await cfApexSteps({ domain, token: dnsToken, flipProxy });
    } catch (e) { closeReader(rl); die(e.message); }
    closeReader(rl);
    r = { ...w, routeAction: 'wrangler', proxied: apex.proxied, flipped: apex.flipped, warnings: apex.warnings };
  } else {
    const token = process.env.CF_TOKEN || process.env.CLOUDFLARE_API_TOKEN;
    try { r = await cfPublish({ domain, ...served, token, flipProxy }); } catch (e) { die(e.message); }
    console.log('  ✓ worker ' + r.script + ' deployed (genesis embedded, ' + r.genHash + ')');
    console.log('  ✓ route ' + r.route + ' ' + r.routeAction);
  }
  if (r.flipped) console.log(`  ✓ proxy enabled on ${r.flipped} apex record${r.flipped > 1 ? 's' : ''}`);
  for (const w of r.warnings) console.log('  ⚠  ' + w);
  if (!r.proxied) { console.log('\n  NOT LIVE YET — the apex is not proxied; nothing to attest.'); process.exit(1); }
  // fail-closed: deployment is only DONE when the live surface attests (§20.1 probes)
  const mirrors = (arg('mirror', '') || '').split(',').filter(Boolean);
  const a = await attestDiscovery({ domain, mirrors, expectHash: r.genHash });
  printChecks(a.checks);
  console.log(`\n  DISCOVERY CONFORMANCE (§20.1): ${a.verdict}${a.verdict === 'PARTIAL' ? '  — no violation; only undeclared properties left unattested (e.g. a mirror)' : ''}`);
  // the flow must never just STOP at a verdict — close the story: what happened, the path to HIGH, housekeeping
  if (a.verdict !== 'FAILED') for (const l of whatsNextSummary({ domain, genHash: r.genHash, checks: a.checks ?? [] })) console.log(l);
  process.exit(a.verdict === 'FAILED' ? 1 : a.verdict === 'PARTIAL' ? 2 : 0);
}

// ─── ust stream <frame…> — the RANGE verdict (F.4): chain, forks, checkpoint, completeness ───────────
// Completeness is NEVER a single document's property — this command is where it legitimately lives.
async function cmdStream() {
  const files = positionals(process.argv.slice(3), STREAM_VALUE_FLAGS);
  if (!files.length) die('usage: ust stream <frame.json…> [--genesis <f>] [--checkpoint <f>]   [--keylog <f,f…>] [--cadence-log <f,f…>]   # range verdict: chain · forks · completeness\n  exit: 0=chain-consistent/complete · 2=provisional/none · 1=broken');
  const frames = [];
  for (const f of files) {
    const { verdict, doc } = verifyRaw(readFileSync(f));   // every frame passes the RAW boundary
    if (!P.isValid(verdict)) die(`frame ${f} does not VERIFY (${verdict.error ?? verdict.result})`);
    frames.push(doc);
  }
  const rd = (flag) => { const v = arg(flag, null); if (v === true) die(`--${flag} needs a value`); if (!v) return null;
    const { verdict, doc } = verifyRaw(readFileSync(v)); if (!P.isValid(verdict)) die(`--${flag} file does not VERIFY (${verdict.error ?? verdict.result})`); return doc; };
  const genesis = rd('genesis');
  const checkpoint = rd('checkpoint');
  // §11.3 continuity — an optional cadence-log (comma-separated files) so `complete` resolves the cadence in
  // force at the interval; without it the genesis cadence (if any) is used.
  const clRaw = arg('cadence-log', null);
  const cadenceLog = (clRaw && clRaw !== true) ? readLogFiles('cadence-log', clRaw) : undefined;
  // the key-log AUTHORIZES the cadence-log (a cadence change must be signed by a genesis/key-log key). Comma-sep.
  const klsRaw = arg('keylog', null);
  const keylog = (klsRaw && klsRaw !== true) ? readLogFiles('keylog', klsRaw) : undefined;
  const r = P.verifyStream(frames, { ...(genesis ? { genesis } : {}), ...(keylog ? { keylog } : {}), ...(checkpoint ? { checkpoint } : {}), ...(cadenceLog ? { cadenceLog } : {}) });
  if (r.error) { console.log(`  ❌ stream BROKEN: ${r.error}${r.detail ? ' — ' + r.detail : ''}`); process.exit(1); }
  console.log('  frames      ' + frames.length);
  console.log('  authority   ' + (frames[0]?.state?.id?.domain_shard ?? '?') + (genesis ? '  (origin: genesis-bound)' : '  (origin: unbound — no --genesis)'));
  console.log('  completeness ' + r.complete
    + (r.hole ? '   (grid hole at ' + r.hole + ' — no frame, no signed gap)' : '')
    + (r.complete === 'chain-consistent' && !r.hole && checkpoint ? '   (no-deletion; `complete` needs a signed genesis cadence + checkpoint from/to)' : '')
    + (r.complete === 'complete' ? '   (no-omission — every grid slot is a frame or a signed gap)' : '')
    + (!checkpoint ? '   (no --checkpoint — unreachable without one)' : ''));
  console.log('\n  completeness is a RANGE verdict over THESE frames — it never upgrades any single document\'s tier');
  process.exit((r.complete === 'chain-consistent' || r.complete === 'complete') ? 0 : 2);
}

// ─── ust forkchoice <doc…> — canonical = anchor-included (§3.1/F.5c). Hold ≥2 docs claiming ONE ust_id with
//     different content (dual-writer race / adversary) → decide WHICH is canonical, deterministically from the chain.
async function cmdForkChoice() {
  const files = positionals(process.argv.slice(3), FORKCHOICE_VALUE_FLAGS);
  if (files.length < 2) die('usage: ust forkchoice <doc.json> <doc.json> [more…] [--genesis <f>] [--keylog <f,f…>] [--no-fork-confirmed] [--offline]\n  decide the CANONICAL document among candidates that claim the SAME ust_id — canonical = the one in the anchored hour root (§3.1/F.5c)\n  exit: 0=CANONICAL · 2=INDETERMINATE (none anchored yet) / MULTI_AUTHORITY · 1=E-PREV (equivocation) / E-MALFORMED');
  const candidates = [];
  for (const f of files) {
    const { verdict, doc } = verifyRaw(readFileSync(f));                 // every candidate passes the RAW boundary
    if (!P.isValid(verdict)) die(`candidate ${f} does not VERIFY (${verdict.error ?? verdict.result})`);
    candidates.push(doc);
  }
  const rd = (flag) => { const v = arg(flag, null); if (v === true) die(`--${flag} needs a value`); if (!v) return null;
    const { verdict, doc } = verifyRaw(readFileSync(v)); if (!P.isValid(verdict)) die(`--${flag} file does not VERIFY (${verdict.error ?? verdict.result})`); return doc; };
  const genesis = rd('genesis');
  const klsRaw = arg('keylog', null);
  const keylog = (klsRaw && klsRaw !== true) ? readLogFiles('keylog', klsRaw) : undefined;
  const noFork = !!arg('no-fork-confirmed', false);
  const offline = !!arg('offline', false);
  // anchor-inclusion is a SUBSTRATE fact — load the same opt-in plugins as `verify`. None installed ⇒ nothing is
  // anchor-included ⇒ honest INDETERMINATE, never a guessed winner.
  const plugins = [], incPlugins = [];
  if (!offline) for (const pkg of ['@ust-protocol/ots-verify', '@ust-protocol/rekor-verify']) {
    try { const m = await import(pkg); if (m.substrateVerify) plugins.push(m.substrateVerify); if (m.inclusionVerify) incPlugins.push(m.inclusionVerify); } catch { /* absent */ }
  }
  const substrateVerify = plugins.length ? P.combineSubstrates(plugins) : undefined;
  const inclusionVerify = incPlugins.length ? P.combineInclusion(incPlugins) : undefined;   // #95 — same plugins, other question
  if (!substrateVerify && !offline) console.error('  ℹ️  no substrate plugin installed — anchor-inclusion cannot be checked → INDETERMINATE. `npm i @ust-protocol/ots-verify` to decide.');
  const r = await P.forkChoice(candidates, { ...(genesis ? { genesis } : {}), ...(keylog ? { keylog } : {}), noForkConfirmed: noFork, offline, context: 'data', substrateVerify });
  const ust = r.ust_id ? `  ust_id ${r.ust_id}` : '';
  if (r.result === 'CANONICAL') {
    console.log(`  ✅ CANONICAL${ust}`);
    console.log(`  content_hash  ${r.content_hash}   (authority ${r.authority}, tier ${r.tier})`);
    if (r.losers.length) console.log(`  losers        ${r.losers.map((l) => l.content_hash).join(', ')}   (valid but not anchor-included for this slot)`);
    process.exit(0);
  }
  if (r.result === 'INDETERMINATE') { console.log(`  ⏳ INDETERMINATE${ust} — ${r.detail || 'no anchor-included candidate yet'}`); process.exit(2); }
  if (r.result === 'MULTI_AUTHORITY') { console.log(`  ℹ️  MULTI_AUTHORITY${ust} — distinct authorities share the ust_id string (not a fork); each is canonical for its own name`); process.exit(2); }
  // round 103 — the refusal carries its CODE in `error`, so print both: a bare `REFUSED` would hide WHICH trust was
  // not earned, which is the one thing this tool exists to say out loud.
  console.log(`  ❌ ${r.result}${r.error ? ' ' + r.error : ''}${ust}${r.detail ? ' — ' + r.detail : ''}`);
  process.exit(1);
}

// ─── ust mirror <domain> — publish a SECOND copy; byte-agreement attested, independence never claimed ──
async function cmdMirror() {
  const domain = process.argv[3];
  if (!domain || domain.startsWith('--')) die('usage: ust mirror <domain> [--publish gh --repo owner/repo [--dir mirror]] [--url g1,g2] [--keylog-url k1]\n  publish EXACT copies of your live identity on a SECOND vendor (§20.1) and ATTEST that they agree byte for byte');
  const tty = !!process.stdin.isTTY;
  const genesisUrls = String(arg('url', '') || '').split(',').filter(Boolean);
  const keylogUrls = String(arg('keylog-url', '') || '').split(',').filter(Boolean);

  if (arg('publish', null) === 'gh') {
    const repoFlag = arg('repo'); if (!repoFlag || repoFlag === true) die('--repo owner/repo is required for --publish gh (a PUBLIC repo — the mirror must be readable by anyone)');
    const dirFlag = arg('dir', 'mirror') === true ? 'mirror' : arg('dir', 'mirror');
    console.log('  ⏳ fetching the canonical bytes from https://' + domain + '/.well-known/…');
    let g; try { g = await fetch(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.text() : Promise.reject(new Error('canonical genesis unreachable: HTTP ' + r.status)))); } catch (e) { die(e.message); }
    let k = null;
    try { const kr = await fetch(`https://${domain}/.well-known/ust-keylog`, { signal: AbortSignal.timeout(10000) }); k = kr.ok ? await kr.text() : null; } catch { k = null; }
    console.log('  ⏳ publishing via YOUR gh CLI (create-or-update, idempotent — this tool holds no credential)…');
        // the WHOLE served set, fetched the same way discovery reads it — a mirror of two of four is a mirror that
    // contradicts itself, and after a supersession it contradicts itself loudly.
    const fetchServed = async (name) => { try { const r = await fetch(`https://${domain}/.well-known/ust-${name}`, { signal: AbortSignal.timeout(10000) }); return r.ok ? await r.text() : null; } catch { return null; } };
    const artifacts = { genesis: g, keylog: k };
    for (const name of DISCOVERY_ARTIFACTS) if (!(name in artifacts)) artifacts[name] = await fetchServed(name);
    for (const [n, v] of Object.entries(artifacts)) console.log(`  ${v == null ? '·' : '✓'} ust-${n}${v == null ? ': not served upstream — will be removed from the mirror' : ''}`);
    let pub; try { pub = await ghMirrorPublish({ repo: repoFlag, dir: dirFlag, artifacts }); } catch (e) { die(e.message); }
    if (pub.removed?.length) console.log('  🗑  removed from the mirror (no longer served): ' + pub.removed.join(', '));
    console.log('  ✅ pushed: ' + pub.genesisUrl);
    if (pub.keylogUrl) console.log('  ✅ pushed: ' + pub.keylogUrl);
    else console.log('  ⬜ the canonical key log is not served yet — redeploy serving first, then re-run mirror');
    genesisUrls.push(pub.genesisUrl);
    if (pub.keylogUrl) keylogUrls.push(pub.keylogUrl);
  } else if (!genesisUrls.length && tty) {
    console.log('  by hand on a SECOND vendor (any static host / object storage / another CDN — NOT your primary):');
    console.log('    1. download the canonical bytes:');
    console.log(`       curl -o ust-genesis  https://${domain}/.well-known/ust-genesis`);
    console.log(`       curl -o ust-keylog   https://${domain}/.well-known/ust-keylog    (if served)`);
    console.log('    2. upload them anywhere PUBLIC on that second vendor');
    console.log('    3. paste the URL(s) — I will FETCH and hash-match them (a claim is not a proof)');
    const rl2 = openReader(createInterface);   // this command asks for a secret afterwards — a bare interface would have it refused
    const gu = (await rl2.question('  genesis mirror URL: ')).trim();
    const ku = (await rl2.question('  key-log mirror URL (Enter to skip): ')).trim();
    closeReader(rl2);
    if (gu) genesisUrls.push(gu);
    if (ku) keylogUrls.push(ku);
  }
  if (!genesisUrls.length) die('nothing to attest: give --url, use --publish gh, or answer interactively');

  console.log('\n  ⏳ attesting the mirror(s) — fetching and hash-matching against the canonical…');
  let m; try { m = await attestMirror({ domain, genesisUrls, keylogUrls }); } catch (e) { die(e.message); }
  const mark = { pass: '✅', fail: '❌', skip: '⬜' };
  for (const r of m.results) console.log(`  ${mark[r.status]}  [${r.kind}] ${r.url}  (${r.detail})`);

  // fold into the FULL §20.1 verdict — an attested mirror is what flips PARTIAL → ATTESTED
  console.log('\n  ⏳ full §20.1 attestation with the mirror declared…');
  const a = await attestDiscovery({ domain, mirrors: genesisUrls, expectHash: m.canonHash });
  printChecks(a.checks);
  const complete = a.verdict === 'ATTESTED' && !m.failed;
  console.log(`\n  RESULT: ${complete ? '✅ COMPLETE — every ATTESTABLE §20.1 property holds, byte-agreement included' : m.failed || a.verdict === 'FAILED' ? '❌ FAILED — fix the ❌ lines above and re-run' : '⬜ PARTIAL — see the ⬜ lines above'}`);
  if (complete) {
    console.log('  vendor-independence is NOT among them: that the copies sit in separate failure domains is');
    console.log('  your operational fact, which no verifier can read out of the bytes (§20.1, F.5o).');
    console.log('  keep the copy URL(s) declared to your consumers (operator profile) and re-attest anytime:');
    console.log(`    ${invocation()} discovery ${domain} --mirror ${genesisUrls[0]}`);
  }
  process.exit(m.failed || a.verdict === 'FAILED' ? 1 : a.verdict === 'PARTIAL' ? 2 : 0);
}

// ─── ust witness rekor <domain> — register the genesis in a transparency log (no-fork evidence, #68) ──
async function cmdWitness() {
  const provider = process.argv[3];
  if (provider !== 'rekor') die('usage: ust witness rekor --domain <d> [--deploy]\n  logs your genesis leaf-root into Sigstore Rekor (a public transparency log) so a verifier can confirm\n  no-fork automatically — seconds, not Bitcoin hours. --deploy also updates the live witness endpoint (CF).');
  const domain = arg('domain'); if (!domain || domain === true) die('--domain is required');

  console.log('\n  🔭 witness (rekor) for ' + domain);
  let genesisText; try { genesisText = await fetch(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(10000) }).then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); }); }
  catch (e) { die('could not fetch the live genesis: ' + e.message + ' — run `ust genesis` / `ust publish cf` first'); }
  const { verdict, doc: genesis } = verifyRaw(genesisText);
  if (!P.isValid(verdict) || genesis.state?.id?.class !== 'genesis') die('the served well-known is not a valid genesis');
  const genHash = P.contentHash(genesis);
  const leafRoot = P.Hbytes('ust:leaf', Buffer.from(genHash, 'utf8'));
  console.log('  genesis ' + genHash);

  console.log('  ⏳ logging the genesis leaf-root into Sigstore Rekor…');
  let rekor; try { rekor = await logToRekor(leafRoot); } catch (e) { die(e.message); }
  console.log('  ✅ Rekor logIndex ' + rekor.logIndex + '  ·  integratedTime ' + new Date(rekor.integratedTime * 1000).toISOString().slice(0, 19) + 'Z');
  const anchor = { root: leafRoot, path: [], anchor: rekor };

  // merge with any anchors already served (e.g. a Bitcoin one) so substrates ACCUMULATE, never replace
  // the live log is fetched for its anchors AND kept whole: it is the prior this witness must extend, not replace.
  // Fetching it twice for two purposes is how the anchors survived while the genesis_log did not.
  let existing = [], priorWitness = null;
  try {
    const r = await fetch(`https://${domain}/.well-known/ust-witness`, { signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      priorWitness = await r.text();
      const wl = JSON.parse(priorWitness);
      const g0 = wl?.genesis_log?.find((x) => x.content_hash === genHash);
      existing = Array.isArray(g0?.anchors) ? g0.anchors : [];
    }
  } catch { /* unreachable ⇒ nothing to merge and nothing to extend */ }
  const merged = [...existing.filter((a) => (a.anchor?.substrate ?? a.substrate) !== 'rekor'), anchor];
  const witness = buildWitnessLog(genesisText, merged, priorWitness);

  if (arg('deploy', false)) {
    console.log('  ⏳ updating the live witness endpoint (CF worker)…');
    let keylogText = null; try { keylogText = await fetch(`https://${domain}/.well-known/ust-keylog`, { signal: AbortSignal.timeout(8000) }).then((r) => r.ok ? r.text() : null); } catch { /* ok */ }
    try { await wranglerDeploy({ domain, ...(await collectServed({ domain, genesisText, genPath: null, keylogText, log: console.log })), witnessText: witness }); } catch (e) { die('deploy failed: ' + e.message + '\n  (the anchor is logged in Rekor; re-run --deploy or update the endpoint by hand)'); }
    console.log('  ✅ witness endpoint updated — verifiers with @ust-protocol/rekor-verify now confirm no-fork automatically');
    console.log('     re-attest:  ${invocation()} verify <slot>   (install ots-verify + rekor-verify)');
  } else {
    console.log('\n  witness-log built (NOT deployed — pass --deploy to update the CF endpoint, or publish it yourself):');
    console.log('  ' + witness);
  }
  process.exit(0);
}

// ─── ust genesis --domain <d> [--profile] [--dns] — the ceremony (#37), orchestrating the core above ──
async function cmdGenesis() {
  const domain = arg('domain'); if (!domain || domain === true) die('usage: ust genesis --domain <name> [--profile bronze|silver|gold] [--dns manual|cf-api] [--publish cf [--auth wrangler] [--flip-proxy]] [--signer <ref>] [--witness url,url] [--max-partitions N] [--cadence SECONDS] [--out .]\n  every option is also asked INTERACTIVELY — the flags only preselect');
  // declared HERE, beside `domain`: the offline branch is read at the remint probe, long before the flags block —
  // declaring it there put it in a temporal dead zone and the whole ceremony died on its first line of work.
  const offline = !!arg('offline', false);   // no network at all — the air-gapped half of a split ceremony
  const signerRef = arg('signer', null);
  // LAZY, like every other askHidden caller. An interface created here takes stdin over, and askHidden's guard then
  // refuses — correctly, because an open readline echoes the passphrase it is trying to hide. When that guard landed
  // its comment claimed "every caller now builds its readline lazily"; this one was not converted, so the guard
  // broke `ust genesis` at silver and gold and nothing noticed, because no gate runs a passphrase ceremony.
  let rl = null;
  const ask = (q) => { rl ??= openReader(createInterface); return rl.question(q); };
  const tty = !!process.stdin.isTTY;
  console.log(`\n  🏛  ust genesis — the HIGH ceremony for ${domain}`);
  console.log('      One run creates your name\'s cryptographic identity and makes it publicly');
  console.log('      discoverable. Everything is verified fail-closed before it is claimed.\n');
  console.log(ceremonyMap(0));

  // ── REMINT GUARD (fail-closed, rc.17): 'absent' is the ONLY state that proceeds silently. A live
  // identity requires typed REMINT; an INDETERMINATE state (network error / garbage / foreign document)
  // also STOPS — those were previously indistinguishable from absence, on an identity-orphaning op.
  // --offline: the crown key is generated on a machine with no network, so it can never leave over one. That
  // claim is only true if this half touches nothing — and the remint probe is the single network call that stands
  // before the files. It cannot run here, so the check it performs becomes the OPERATOR'S, stated rather than
  // skipped: minting over a live identity orphans it, and offline this tool cannot tell whether one exists.
  if (offline) {
    console.log('\n  ✈️  OFFLINE — no network will be touched. This half produces keys and documents only.');
    console.log('     I CANNOT check whether an identity is already live at ' + domain + '. If one is, this mints a');
    console.log('     SUCCESSOR: the publish half will chain it (the predecessor keeps its anchors and is marked');
    console.log('     superseded). If you meant to add a key instead, stop — that is `ust rotate`, not a ceremony.');
    if (tty) {
      const a = (await ask('     type OFFLINE to confirm you know which of the two you are doing: ')).trim();
      if (a !== 'OFFLINE') { rl?.close(); die('aborted — nothing was minted'); }
    }
  } else {
    const probe = await remintProbe({ domain });
    if (probe.status === 'live') {
      console.log(`\n  ⚠️  an identity for ${domain} is ALREADY LIVE: ${probe.hash.slice(0, 28)}…`);
      console.log('     re-running the ceremony MINTS A NEW IDENTITY and orphans the live one.');
      console.log('     KEY ROTATION is different: a key-log APPEND under the SAME identity (root stays,');
      console.log('     old documents stay valid) — never a new ceremony.');
      if (!arg('remint', false)) {
        if (!tty) { rl?.close(); die('an identity is already live — pass --remint to consciously replace it'); }
        const a = (await ask('     type REMINT to replace it, anything else aborts: ')).trim();
        if (a !== 'REMINT') { rl?.close(); die('aborted — the live identity stays untouched'); }
      }
    } else if (probe.status === 'indeterminate' && !arg('remint-unchecked', false)) {
      console.log(`\n  ⚠️  REMINT STATUS INDETERMINATE: ${probe.detail}`);
      console.log('     I cannot PROVE no identity is live at ' + domain + ' — and minting over a live one orphans it.');
      if (!tty) { rl?.close(); die('remint status indeterminate — pass --remint-unchecked to proceed anyway'); }
      const a = (await ask('     type UNCHECKED to proceed anyway, anything else aborts: ')).trim();
      if (a !== 'UNCHECKED') { rl?.close(); die('aborted — resolve the well-known state first (or --remint-unchecked)'); }
    }
  }

  // ── the INTERVIEW (rc.10, owner catch): every choice IS a choice — flags preselect, otherwise the
  // ceremony asks, each question carrying its meaning. A dangling value-flag is an ERROR headless and
  // just re-asked in a tty. Nothing is silently dictated.
  const askOr = async (flag, question, def, validate) => {
    let v = arg(flag, null);
    if (v === true) { if (!tty) die(`--${flag} needs a value`); v = null; }
    if (v === null && tty) { const a = (await ask(question)).trim(); v = a === '' ? def : a; }
    if (v === null) v = def;
    // An UNSET optional reaches the validator as itself, not as the string "null". Every optional validator here is
    // written `v === null || <check>`, and stringifying first turned "left blank" into the literal "null", which no
    // check accepts — so declining an optional field ABORTED the ceremony. It survived because nothing ran a
    // ceremony to the end; the only exercisable profile skipped the prompts that have defaults.
    if (validate && !validate(v === null || v === undefined ? null : String(v))) die(`--${flag}: "${v}" is not a valid value`);
    return v;
  };

  console.log('\n  ⚙️  a few choices, Enter accepts the [default]:');
  console.log('\n  profile = how much ceremony rigor:');
  console.log('    bronze  quick floor (plain backup)     silver  software root + ENCRYPTED backup');
  console.log('    gold    HARDWARE root (pkcs11/air-gap) — refused honestly until this CLI can drive one');
  const profile = await askOr('profile', '  profile [silver]: ', 'silver', (v) => ['bronze', 'silver', 'gold'].includes(v));
  if (profile === 'gold') { rl?.close(); die(GOLD_REFUSAL); }   // refuse NOW — not after three more questions

  console.log('\n  capacity = max partitions your documents may DECLARE (signed into the genesis,');
  console.log('  ceremony-earned; ABS ceiling 4096). More sources/fields later ⇒ pick headroom now.');
  const defP = profile === 'gold' ? 256 : profile === 'silver' ? 64 : null;
  const maxP = await askOr('max-partitions', `  max_partitions [${defP ?? 'floor 64'}]: `, defP, (v) => v === null || (Number(v) > 0 && Number(v) <= 4096));

  // §11.3 C — the SIGNED stream cadence (seconds). Bakes into the genesis so a range verdict can reach
  // `complete` (no-omission): every expected grid slot must be a frame or a signed gap. Optional — an operator
  // that makes no completeness claim leaves it unset (its streams verify at `chain-consistent`, honest).
  console.log('\n  📐  CADENCE (optional) — the stream slot interval in SECONDS. Signed here so the completeness');
  console.log('  verdict is grid-checked (`complete`), not just no-deletion (`chain-consistent`). Leave blank if');
  console.log('  you make no completeness claim (e.g. a lossy free tier). noosphere: 30.');
  const cadence = await askOr('cadence', '  cadence [none]: ', null, (v) => v === null || (Number.isInteger(Number(v)) && Number(v) > 0));

  // §12.3 + §12.1 P2 — the last two genesis fields, and the ONLY two that can never be added later: changing
  // either means a new genesis, i.e. a supersession. Both default to none, because an operator who does not want
  // them should not be talked into them — but the consequence is stated rather than hidden.
  console.log('\n  🔑  RECOVERY (optional) — re-root authority in DOMAIN CONTROL. If the root key is lost or');
  console.log('  compromised, a threshold of these keys can supersede the genesis; without it, the only recovery is');
  console.log('  a fresh name. Keys are generated here and written beside the root. SET IT NOW OR NEVER: adding it');
  console.log('  later requires a new genesis.');
  const recN = await askOr('recovery-keys', '  recovery keys [0]: ', 0, (v) => Number.isInteger(Number(v)) && Number(v) >= 0 && Number(v) <= 16);
  let recovery = null, recoverySigners = [];
  if (Number(recN) > 0) {
    const dflt = Math.min(2, Number(recN));
    const th = await askOr('recovery-threshold', `  threshold of ${recN} [${dflt}]: `, dflt, (v) => Number(v) >= 1 && Number(v) <= Number(recN));
    recoverySigners = await Promise.all(Array.from({ length: Number(recN) }, () => W.generateSigner({ extractable: true })));
    recovery = { keys: Object.fromEntries(recoverySigners.map((k) => [k.key_id, k.pub])), threshold: Number(th) };
  }

  console.log('\n  🧾  CHECKPOINT AUTHORITY (optional) — the key allowed to sign §12.3 authority checkpoints, which let');
  console.log('  a verifier skip a long key log instead of walking every event. Generated here. SET IT NOW OR NEVER.');
  const wantCA = await askOr('checkpoint-authority', '  checkpoint authority [no]: ', 'no', (v) => ['yes', 'no', 'y', 'n'].includes(String(v).toLowerCase()));
  let checkpointAuthority = null, caSigner = null;
  if (/^y/i.test(String(wantCA))) {
    caSigner = await W.generateSigner({ extractable: true });
    checkpointAuthority = { key_id: caSigner.key_id, pub: caSigner.pub };
  }

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
  console.log(`\n  ⚙️  profile ${profile} · max_partitions ${maxP ?? '(floor 64)'}${arg('max-transcript-bytes', null) && arg('max-transcript-bytes', null) !== true ? ' · max_transcript_bytes ' + arg('max-transcript-bytes', null) : ''} · road ${publishMode === 'cf' ? 'cloudflare one-click' : 'by hand'}`);
  console.log(`      files → ${outDir === '.' ? process.cwd() : outDir}  (override with --out)`);
  // one token, asked ONCE at first need — steps 3 and 4 share it (never a double paste-prompt)
  let dnsTokenMemo = null;
  const getDnsToken = async () => (dnsTokenMemo ??= await resolveDnsToken(ask));

  // THE LAST REVERSIBLE MOMENT. Three fields can be set here and NOWHERE ELSE: declining one is permanent for this
  // identity, and the resulting genesis verifies perfectly while quietly lacking the capability. That is the exact
  // shape an operator cannot notice on their own — nothing is broken, nothing warns, and the loss surfaces on the
  // day it is needed. The end-of-run summary repeats this, but a warning printed AFTER an irreversible act is not a
  // control. So the consequences are stated here, before anything is sealed, and an interactive operator must say
  // yes to them. A reserved test name skips the confirmation (there is nothing behind it to lose).
  const limits = ceremonyLimits({ cadence, recovery, checkpointAuthority });
  if (limits.length && !RESERVED_TEST_NAME.test(domain)) {
    for (const l of limits) console.log(l);
    if (tty) {
      const a = (await ask('  type YES to mint an identity with those limits, anything else goes back: ')).trim();
      if (a !== 'YES') { rl?.close(); die('aborted — nothing was minted. Re-run and set the fields you want; they cannot be added later.'); }
    } else {
      console.log('  (non-interactive — proceeding; the limits above are PERMANENT for this identity)');
    }
  }

  // 1–2. root key + genesis + key-log[0], all self-checked (fail-closed) inside buildCeremony
  const maxBytes = arg('max-transcript-bytes', null);
  if (maxBytes === true) { rl?.close(); die('--max-transcript-bytes needs a value'); }
  // §12.2 — role separation is DECLARED at the ceremony and NOWHERE else: adding it later means superseding the
  // genesis, so a ceremony that cannot offer it makes the feature unreachable for every publisher.
  const rolesArg = arg('roles', null);
  let roles = null;
  if (rolesArg && rolesArg !== true) {
    roles = String(rolesArg).split(',').map((r) => r.trim()).filter(Boolean);
    const bad = roles.filter((r) => r !== 'data' && r !== 'issuance');
    if (bad.length) die(`--roles takes the OPERATING roles only (data, issuance) — got ${bad.join(', ')}. The authorizing roles are ceremony-structural and set by their own flags, and a role names the chain its key serves (§17).`);
    if (!roles.length) die('--roles was given with no role — omit the flag to publish without role separation');
  }
  let built; try { built = await buildCeremony({ domain, profile, maxP, maxBytes, cadence, checkpointAuthority, recovery, roles, signerRef }); }
  catch (e) { rl?.close(); die(e.message); }
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
    // A DOOR FOR THE HARNESS IS A DOOR. The passphrase is asked interactively, which is right for a person — but
    // then no gate can perform a silver ceremony end to end, and that gap is exactly what let a broken ceremony
    // ship for six release candidates. So the non-interactive path exists, and it opens ONLY in a room where there
    // is nothing to steal: a name reserved by RFC 2606/6761, which cannot exist on the internet. Scripting the
    // passphrase of a REAL crown key is refused loudly rather than quietly allowed.
    if (RESERVED_TEST_NAME.test(domain) && process.env.UST_CEREMONY_PASSPHRASE) {
      pass = process.env.UST_CEREMONY_PASSPHRASE;
      if (pass.length < 8) die('UST_CEREMONY_PASSPHRASE is shorter than 8 characters');
      console.log(`\n  🧪 ${domain} is a RESERVED test name — passphrase taken from UST_CEREMONY_PASSPHRASE.`);
      console.log('     This path is refused for any real name: a scripted crown passphrase is not a ceremony.');
    } else {
      if (process.env.UST_CEREMONY_PASSPHRASE)
        die(`UST_CEREMONY_PASSPHRASE is set but "${domain}" is not a reserved test name (.test/.example/.invalid/.localhost or example.com|net|org).\n`
          + '  A real crown passphrase is never taken from the environment — it would land in shell history, process\n'
          + '  listings and CI logs. Remove the variable and run the ceremony interactively.');
      console.log('\n  🧊 The root key is about to be written to disk ENCRYPTED. The passphrase you set now');
      console.log('     is the ONLY way to open that backup — store the file and the phrase in DIFFERENT');
      console.log('     places (split custody). You will need it roughly once a year (rotate/revoke).');
      // askHidden must OWN stdin. Building the interface lazily is necessary and NOT sufficient: by this point the
      // ceremony has already asked several questions, so the interface exists and would echo the passphrase — the
      // guard then refuses and the whole ceremony dies one step from writing its files. So hand stdin back: close
      // it here and null the handle, and the lazy getter re-creates it for any question that follows.
      // (This path is the one an operator actually walks. It went untested because the offline rehearsal supplied
      //  the passphrase through the reserved-name environment variable, which skips askHidden entirely.)
      // …and inside the LOOP, not once before it. askHidden's own no-tty fallback delegates to `ask`, which
      // re-creates the interface — so a second attempt (a short passphrase, or any non-tty run) met an open reader
      // again and died on the retry rather than the first try. Measured: close() drops the stdin listener
      // synchronously, so re-closing each iteration is exact rather than hopeful.
      // BOUNDED. An unbounded retry loop spins forever the moment stdin cannot answer — an exhausted pipe, a
      // detached terminal, a script that fed fewer lines than the ceremony asks. It burns a core and prints the
      // same prompt until someone notices, which on a machine deliberately cut off from the network may be a while.
      for (let tries = 1; pass.length < 8; tries++) {
        if (tries > 5) { rl?.close(); die('no usable passphrase after 5 attempts — stdin cannot answer (an exhausted pipe or a detached terminal). Run the ceremony from a real terminal.'); }
        rl = closeReader(rl);
        pass = await askHidden('     set the passphrase (≥8 chars): ', ask);
      }
      rl = closeReader(rl);   // hand stdin back; the next question opens a fresh interface
    }
  }
  const backup = pass ? encryptKey(pkcs8, pass) : pkcs8.toString('base64');
  // custody hardening (line-review P1): key material is 0600 and NEVER silently overwritten ('wx') —
  // a local re-run cannot clobber an existing root backup; public identity docs also refuse overwrite.
  const writeSecret = (path, data) => writeFileSync(path, data, { mode: 0o600, flag: 'wx' });
  const writePublic = (path, data) => writeFileSync(path, data, { flag: 'wx' });
  try {
    writeSecret(`${outDir}/genesis-key${pass ? '.enc' : ''}.b64`, backup);
  // operational key = the WARM daily signer. Written PLAIN base64 PKCS8 because the
  // producer loads it non-interactively from its signing-key env. It is NOT cold-store:
  // move it into the producer's secret store, then delete this file — never commit it.
    writeSecret(`${outDir}/operational-key.b64`, opPkcs8.toString('base64'));
    // A recovery set that is signed into the genesis and NOT persisted is worse than none: the document would
    // advertise a recovery the operator cannot perform. Same for the checkpoint authority. They are written under
    // the same 0600 + refuse-overwrite discipline as the root, and the summary tells the operator to split them —
    // a threshold whose keys all live in one directory is a threshold of one.
    for (const [i, k] of recoverySigners.entries())
      writeSecret(`${outDir}/recovery-key-${i}.b64`, Buffer.from(await crypto.subtle.exportKey('pkcs8', k.privateKey)).toString('base64'));
    if (caSigner)
      writeSecret(`${outDir}/checkpoint-authority-key.b64`, Buffer.from(await crypto.subtle.exportKey('pkcs8', caSigner.privateKey)).toString('base64'));
    writePublic(`${outDir}/ust-genesis`, JSON.stringify(genesis));
    writePublic(`${outDir}/ust-keylog-0`, JSON.stringify(keylog0));
  } catch (e) {
    rl?.close();
    die(e.code === 'EEXIST'
      ? `refusing to overwrite an existing ceremony file (${e.path}). Move the previous ceremony's files away (or run with --out <fresh dir>) and re-run — key material is never silently clobbered.`
      : e.message);
  }
  // COUNTED, not asserted: the number was the literal "four" until the ceremony could also emit recovery and
  // checkpoint-authority keys. A count that does not enumerate what it counts is how an operator walks away
  // believing they hold every file the ceremony produced.
  const written = 4 + recoverySigners.length + (caSigner ? 1 : 0);
  console.log(`\n  📦 ${written} files written to ` + outDir + ':');
  console.log('     ust-genesis + ust-keylog-0          → PUBLIC identity documents (verifiable by anyone)');
  console.log(`     genesis-key${pass ? '.enc' : ''}.b64${pass ? '' : '    '}                 → 🧊 COLD crown backup (file + passphrase apart)`);
  console.log("     operational-key.b64                 → 🔥 WARM daily signer → your producer's signing-key secret, then DELETE");
  if (recoverySigners.length) {
    console.log(`     recovery-key-0…${recoverySigners.length - 1}.b64${' '.repeat(Math.max(1, 18 - String(recoverySigners.length - 1).length))}→ 🧊 ${recovery.threshold} of ${recoverySigners.length} can supersede this genesis`);
    console.log('       SPLIT THEM — a threshold whose keys share one directory is a threshold of one.');
  }
  if (caSigner) console.log('     checkpoint-authority-key.b64        → 🧊 signs §12.3 authority checkpoints (skip-the-key-log)');
  console.log('     self-check: genesis + key-log verify ✓ (this tool never emits what it has not verified)');

  // THE CUT. Everything below this line needs the network: DNS, serving, the live gate, the witness. Offline stops
  // here with the files on disk and the exact handoff — the second half is an ordinary `ust publish`, which needs
  // only the PUBLIC documents. The crown key never travels.
  if (offline) {
    rl?.close();
    for (const l of offlineHandoff({ domain, outDir, genHash })) console.log(l);
    return;
  }

  // 3. DNS (profile A) — manual paste or CF one-click (upsert + DoH readback)
  console.log('\n' + ceremonyMap(2));
  const txt = `ust-genesis=${genHash}`;
  if (dnsMode === 'cf-api') {
    console.log('\n  ▶️  3/5 🌐 the DNS half needs the DNS-only token (asked NOW because it is needed NOW):');
    let res;
    try {
      const dnsToken = await getDnsToken();   // env if set; otherwise the prefilled link + a paste (asked once)
      console.log('  ⏳ writing _ust.' + domain + ' TXT via the Cloudflare API (upsert + DoH readback)…');
      res = await cfUpsert({
        domain, txt, genHash, token: dnsToken,
        onAttempt: (i, n) => console.log(`     ⏳ readback ${i}/${n} — the resolver still serves the previous record (TTL up to 300 s), waiting…`),
      });
    } catch (e) { rl?.close(); die(e.message); }
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
        // the key log rides ALONG (a verifier needs genesis AND key log) — served as a JSON array,
        // so a future rotation is an APPEND + redeploy, never a rewrite
        const w = await wranglerDeploy({ domain, ...(await collectServed({ domain, genesisText: JSON.stringify(genesis), genPath: outDir + "/ust-genesis", keylogText: JSON.stringify([keylog0]), log: console.log })) });
        const apex = await cfApexSteps({ domain, token: await getDnsToken(), flipProxy: !!arg("flip-proxy", false) });
        pub = { ...w, routeAction: 'wrangler', proxied: apex.proxied, flipped: apex.flipped, warnings: apex.warnings };
      } else {
        pub = await cfPublish({ domain, ...(await collectServed({ domain, genesisText: JSON.stringify(genesis), genPath: outDir + "/ust-genesis", keylogText: JSON.stringify([keylog0]), log: console.log })), token: process.env.CF_TOKEN || process.env.CLOUDFLARE_API_TOKEN, flipProxy: !!arg('flip-proxy', false) });
      }
    } catch (e) { rl?.close(); die(e.message); }
    console.log('  ✅ worker ' + pub.script + ' + route ' + pub.route + ' (' + pub.routeAction + (pub.flipped ? ', proxy enabled on apex' : '') + ')');
    for (const w of pub.warnings) console.log('  ⚠️  ' + w);
    if (!pub.proxied) { rl?.close(); die('apex is not proxied — the route cannot fire. Re-run with --flip-proxy (NOTE: puts the whole site behind CF), or enable the proxy manually and re-run.'); }
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
      else console.log('  ⚠️  🌐 the _ust TXT is not visible via DoH yet (registrar propagation) — re-attest later:  ${invocation()} discovery ' + domain);
    }
    // §20.1 probe (3), WARNING-level here: BINDING is fail-closed above; a serving-contract violation is
    // fixable post-hoc without redoing the ceremony. `ust discovery <domain>` re-attests all four anytime.
    try {
      const rand = `q${randomBytes(6).toString('hex')}=${randomBytes(6).toString('hex')}`;
      const baseline = JSON.stringify(liveDoc); void baseline;
      const a = await fetch(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(10000) }).then((r) => r.text());
      const probed = await fetch(`https://${domain}/.well-known/ust-genesis?${rand}`, { signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`))));
      if (probed === a) console.log('  ✅ query-robustness probe: an unknown ?query returns byte-identical bytes (§20.1)');
      else console.log('  ⚠️  §20.1 SERVING: the response VARIES with an unknown query parameter — cache-key amplification is open; fix the cache config, then `${invocation()} discovery ' + domain + '`');
    } catch (e) { console.log('  ⚠️  §20.1 SERVING: query-robustness probe inconclusive (' + e.message + ') — run `${invocation()} discovery ' + domain + '` later'); }
  } catch (e) { rl?.close(); die(e.message); }

  // 5. witnesses + anchor — PREPARED here; the operator runs the exchange + anchor
  console.log('\n' + ceremonyMap(4));
  const witnesses = (arg('witness', '') || '').split(',').filter(Boolean);
  const [head, ...rest] = stageSummary({ genHash, witnesses, profile });
  console.log('\n  ▶️  5/5 ⚓ ' + head);
  for (const line of rest) console.log('       ' + line);

  for (const line of ceremonySummary({ domain, genHash, opKeyId: op.key_id, maxP, cadence, outDir, encrypted: !!pass, recovery, checkpointAuthority })) console.log(line);
  rl?.close();
}

// ─── UST#66 `ust rotate` — key-log lifecycle: APPEND a rotation (never re-mint). rc.15 added the remint guard;
//     this is the missing half. Continuity law (§12.2): old docs stay valid under the key that was active at
//     THEIR anchored time, so a rotation NEVER invalidates history. Testable core + CLI wrapper.
export async function rootSignerFrom(pkcs8, rootPubB64url) {
  const priv = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  const pubKey = await crypto.subtle.importKey('raw', Buffer.from(rootPubB64url, 'base64url'), { name: 'Ed25519' }, true, ['verify']);
  const signer = await W.signerFromKeys(priv, pubKey);
  if (signer.pub !== rootPubB64url) throw new Error('decrypted root key does NOT match the served genesis pub — wrong backup');
  return signer;
}
// Build the grown key-log. Signs the new op key with the ROOT (a current valid key, §12.2), prev-chained;
// optionally revokes the superseded op key with a reason. Refuses to REWRITE (input MUST be a prefix). Pure.
// §12.2/§F.5e.1 — add a key BESIDE the current one, not in place of it. This is the operation `rotate` cannot
// express and inheritance cannot either: `supersedes` PROPAGATES a role down a lineage and never INTRODUCES one,
// so a key for a DIFFERENT purpose has no lineage to inherit from and must state its own role. Root-signed like
// every key-log mutation (§F.5e.3).
export async function addKeylogKey({ genesis, keylog, rootSigner, role = null, time, ustId }) {
  const domain = genesis.state.id.domain_shard;
  // §12.2 — whether a `role` is REQUIRED, FORBIDDEN, or wrong is a property of the SERVED GENESIS, never of the
  // command. Until round 84 the dispatcher asserted it as a property of the command: `--role` was demanded first
  // and the declaration checked second, so a publisher that declares no roles had no path to a parallel key at all
  // — only `ust rotate`, which replaces. The protocol admits exactly what the tool refused (`role-01`, active_count 2),
  // and the refusal even named a GENESIS SUPERSESSION as the remedy: re-rooting a live identity to add a key that
  // needs no ceremony. The rule lives here, in the testable core, rather than in the dispatcher, which is not
  // exported and therefore cannot be asserted against.
  const declared = genesis.state?.data?.genesis?.value?.roles;
  const declares = Array.isArray(declared) && declared.length > 0;
  if (declares && !role) throw new Error(`this genesis DECLARES role separation (${declared.join(', ')}), so a parallel key must state its own role: --role <${declared.join('|')}>. Inheritance propagates a role down a lineage and can never introduce one (§F.5e.1), and a missing field must not be the strongest possible claim.`);
  if (declares && !declared.includes(role)) throw new Error(`--role ${role} is not one this genesis declared (${declared.join(', ')})`);
  if (!declares && role) throw new Error(`this genesis declares NO role separation, so a \`role\` on a key-log entry is a field the verifier cannot act on and the entry would be E-MALFORMED (§12.2, §F.5e.2). Add the key WITHOUT --role; declaring roles is a separate ceremony act that supersedes the genesis.`);
  const prev = keylog.length ? P.contentHash(keylog[keylog.length - 1]) : P.contentHash(genesis);
  const newKey = await W.generateSigner({ extractable: true });
  const entry = await W.seal(P.buildKeyLogEntry({ domain_shard: domain, ust_id: ustId, key_id: rootSigner.key_id }, time,
    { op: 'add', pub: newKey.pub, new_key_id: newKey.key_id, ...(role ? { role } : {}) }, prev), rootSigner);
  return { keylog: [...keylog, entry], newKey };
}
export async function rotateKeylog({ genesis, keylog, rootSigner, reason = null, compromisedSince = null, supersedesKeyId = null, time, ustId }) {
  const domain = genesis.state.id.domain_shard;
  if (!Array.isArray(keylog)) throw new Error('key-log is not a JSON array');
  // §12.2 — "the succession STATED rather than inferred from adjacency". Until round 82 this line read
  // `[...keylog].reverse().find(op === 'add')`: the nearest preceding add, which is adjacency, in the producer of
  // the very field added to remove adjacency from the reader. With one operational key that was right by accident.
  // `ust key add --role` (round 79) made two active keys ordinary, and then the subject was whichever key happened
  // to be added last — so a rotation superseded the wrong key, `role` was inherited from the wrong lineage, and
  // `--reason compromised` TERMINALLY revoked a key the operator never named.
  // The subject now comes from the RESOLVED active set and is named by the operator. Ambiguity REFUSES: a ceremony
  // that can permanently retire a key must not choose which one on the operator's behalf.
  const ks = P.resolveKeys(genesis, keylog);
  if (ks.error) throw new Error(`the served key log does not resolve (${ks.error}): ${ks.detail || ''} — refusing to rotate against a log I cannot read`);
  const rootKid = P.keyId(genesis.state.data.genesis.value.pub);
  const subjects = [...ks.active.keys()].filter((k) => k !== rootKid);   // the root is not a rotation subject: §12.1 P2 re-roots it
  const describe = (k) => `${k}${ks.roles?.get(k) ? ` (role ${ks.roles.get(k)})` : ''}`;
  let subject;
  if (supersedesKeyId) {
    if (!subjects.includes(supersedesKeyId)) throw new Error(`--key-id ${supersedesKeyId} is not an ACTIVE operational key of this log. Active: ${subjects.map(describe).join(', ') || '(none)'}`);
    subject = supersedesKeyId;
  } else if (subjects.length === 1) {
    subject = subjects[0];                                             // unique: naming it adds nothing a reader could not derive
  } else if (subjects.length === 0) {
    throw new Error('this key log has no ACTIVE operational key to rotate — `ust key add --role <data|issuance>` introduces one');
  } else {
    throw new Error(`this log has ${subjects.length} ACTIVE operational keys, so a rotation must NAME its subject: --key-id <key_id>. Candidates: ${subjects.map(describe).join(', ')}`);
  }
  const currentOp = { pub: ks.active.get(subject), kid: subject };
  const newOp = await W.generateSigner({ extractable: true });
  const prev = keylog.length ? P.contentHash(keylog[keylog.length - 1]) : P.contentHash(genesis);
  // #75 §12.2 — the ROOT signs, ADDING the new operational key: the root is NOT superseding ITSELF (that is what
  // `rotate` means — "authorized by the key it supersedes"), so this is `add`; retiring the old operational key is
  // the SEPARATE `revoke` below. (A key that rolls ITSELF forward would sign an `op:'rotate'`.)
  // `supersedes` STATES the succession the two-event replacement used to leave implicit (rev97, §F.5e.0). Without it
  // an `add` followed by a `revoke` is two unrelated facts that a reader infers a relation between by adjacency —
  // and adjacency is not a relation. With it, the successor's lineage is readable, which is what role inheritance
  // (§F.5e.1) derives from. It grants nothing by itself: the entry is authorized by the ROOT either way.
  // NO `role` here, and that closes thelabmd/UST-Protocol#108 in the two-acts direction: a rotation names a SUBJECT
  // and the successor INHERITS that subject's role (§F.5e.1 — inheritance propagates, never introduces). Changing
  // what a key is FOR is an additive act, `ust key add --role`, because a rotation removes its subject from `active`
  // — so a rotation that also changed the role would silently retire the old role along with the old key.
  const supersedes = currentOp.kid;
  const rotate = await W.seal(P.buildKeyLogEntry({ domain_shard: domain, ust_id: ustId, key_id: rootSigner.key_id }, time, { op: 'add', pub: newOp.pub, new_key_id: newOp.key_id, supersedes }, prev), rootSigner);
  const out = [...keylog, rotate];
  if (reason) {
    if (reason !== 'retired' && reason !== 'compromised') throw new Error('--reason must be retired|compromised');
    if (reason === 'compromised' && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(compromisedSince || '')) throw new Error('--reason compromised requires --compromised-since <RFC3339-Z>');
    const oldPub = currentOp.pub;
    const revoke = await W.seal(P.buildKeyLogEntry({ domain_shard: domain, ust_id: ustId, key_id: rootSigner.key_id }, time, { op: 'revoke', pub: oldPub, reason, ...(reason === 'compromised' ? { compromised_since: compromisedSince } : {}) }, P.contentHash(rotate)), rootSigner);
    out.push(revoke);
  }
  for (let i = 0; i < keylog.length; i++) if (P.contentHash(keylog[i]) !== P.contentHash(out[i])) throw new Error('refuse: rotation must APPEND, not rewrite (entry ' + i + ' changed)');
  return { keylog: out, newOp, supersededKeyId: subject, revokedPub: reason ? currentOp.pub : null };
}
// §12.2/§F.5e.1 — `ust key add --role`: a key BESIDE the current one. Distinct from `ust rotate`, which REPLACES
// and whose successor inherits its predecessor's role; a parallel key has no lineage, so it must state its own.
// The first screen, and ONLY the first screen: the mascot is shown once, above the map, never per command.
// TTY-gated — a redirected or piped run must see exactly what it sees today, because a script parses this.
// The art is a committed source artifact (seal_mini_square.txt) rendered from the SVG beside it; it is read
// rather than inlined so the picture and the file cannot drift into two versions of one drawing.
function banner() {
  if (!process.stderr.isTTY) return '';
  let art;
  try { art = readFileSync(new URL('./seal_mini_square.txt', import.meta.url), 'utf8').replace(/\n+$/, ''); }
  catch { return ''; }   // a missing asset must never be the reason a tool refuses to print its help
  // The version is DERIVED from the core, never written here. `v1.0` is the WIRE version — what a document must
  // conform to — and `rc40` is the protocol package's candidate, which is the number that decides what a check
  // MEANS; naming the CLI's own version instead would be precision about the wrong thing (the same call round 67
  // made for `ust discovery`). A hand-typed version on a first screen is a claim that goes stale silently.
  const rc = /-rc\.(\d+)$/.exec(P.VERSION.spec)?.[1];
  const SIDE = { 1: 'UST Protocol', 2: 'RSS for State', 4: `v${P.VERSION.wire}${rc ? ' rc' + rc : ''}` };
  const COL = 37;
  const lines = art.split('\n').map((l) => '  ' + l);
  // A NARROW TERMINAL EATS IT, so the side text is dropped rather than wrapped: wrapped, it would break the art's
  // alignment for every row below it, and a broken first screen is worse than a plain one.
  const needs = COL + Math.max(...Object.values(SIDE).map((s) => s.length));
  const room = !process.stderr.columns || process.stderr.columns >= needs;
  // one blank line ABOVE as well as below: printed with no leading break the art sits flush against the shell
  // prompt, which reads as overflow rather than as the start of the screen.
  return '\n' + lines.map((l, i) => (room && SIDE[i] ? l.padEnd(COL) + SIDE[i] : l)).join('\n') + '\n\n';
}
// NOT exported: a command is not part of the package's API — the dispatcher is in this module, and the gates that
// look for it read the SOURCE by name. The API is the binary plus the testable cores (`addKeylogKey` below).
async function cmdKey() {
  const sub = process.argv[3];
  if (sub !== 'add') die('usage: ust key add --domain <d> --root <encrypted-root.b64> [--role <data|issuance>] [--keylog <served array file>] [--out .]\n  APPENDS a key BESIDE the current one (never replaces it — that is `ust rotate`).\n  --role is REQUIRED if the served genesis DECLARES role separation and REFUSED if it does not: which one is a\n  property of that genesis, not of this command, so it is read from the genesis rather than demanded up front.');
  const domain = arg('domain');
  if (!domain || domain === true) die('--domain <d> required');
  const rootFile = arg('root'); if (!rootFile || rootFile === true) die('--root <encrypted root backup .b64> required (the cold crown key — every key-log mutation is root-signed, §F.5e.3)');
  const roleArg = arg('role', null); const role = (roleArg && roleArg !== true) ? roleArg : null;
  const get = discoveryFetcher(domain);
  let genesis; try { genesis = JSON.parse(await get('/.well-known/ust-genesis')); } catch (e) { die('cannot fetch genesis for ' + domain + ': ' + (e.message || e)); }
  if (!P.isValid(P.verify(genesis, { context: 'key' }))) die('served genesis does not VERIFY');
  const klFile = arg('keylog', null);
  let keylog = [];
  try { if (klFile && klFile !== true) { const parsed = parseKeylogRaw(readFileSync(String(klFile), 'utf8')); if (parsed.err) throw new Error(parsed.err); keylog = parsed.entries; }
        else { const parsed = parseKeylogRaw(await get('/.well-known/ust-keylog')); if (parsed.err) throw new Error(parsed.err); keylog = parsed.entries; } }
  catch (e) { die('cannot load the key-log: ' + (e.message || e)); }
  // LAZY, like every other askHidden caller: an interface built EAGERLY takes stdin over and askHidden's guard
  // then refuses rather than echo the secret. And hand stdin back BEFORE asking — here nothing is open yet, so
  // it is a no-op, which is the point: the property holds by CONSTRUCTION, so a question added above it later
  // cannot silently reintroduce the refusal. That is exactly how the genesis ceremony broke.
  let rl = null;
  const ask = (q) => { rl ??= openReader(createInterface); return rl.question(q); };
  rl = closeReader(rl);
  const pass = await askHidden('  🔑 root passphrase: ', ask);
  rl = closeReader(rl);
  let rootSigner;
  try { rootSigner = await rootSignerFrom(decryptKey(readFileSync(rootFile, 'utf8').trim(), pass), genesis.state.data.genesis.value.pub); }
  catch (e) { die(e.message.includes('match') ? e.message : 'decrypt failed — wrong passphrase or corrupt backup'); }
  const { ust_id, time } = W.nowFrame();
  let grown; try { grown = await addKeylogKey({ genesis, keylog, rootSigner, role, time, ustId: ust_id }); }
  catch (e) { die(e.message); }
  // rev95 self-check: assert what the ceremony PRESERVES, from what it holds — the new key is ACTIVE after the
  // grown log and carries the role asked for. Not a property of the world; no network, no name authority.
  const ks = P.resolveKeys(genesis, grown.keylog);
  if (ks.error) die('self-check FAILED: the grown key-log does not resolve (' + ks.error + ': ' + (ks.detail || '') + ')');
  if (!ks.active.has(grown.newKey.key_id)) die('self-check FAILED: the new key is NOT in the active set after the grown log');
  // `roles` carries no entry for an unroled key, so ABSENT must compare equal to "no role asked for" — otherwise
  // the undeclared path this round opened would die on the ceremony's own self-check, which is how the genesis
  // ceremony broke once already.
  const gotRole = ks.roles.get(grown.newKey.key_id) ?? null;
  if (gotRole !== role) die(`self-check FAILED: the new key resolves with role ${gotRole ?? '(none)'}, not ${role ?? '(none)'}`);
  const outDir = (arg('out', null) && arg('out', null) !== true) ? arg('out', null) : '.';
  writeFileSync(`${outDir}/ust-keylog`, JSON.stringify(grown.keylog, null, 2) + '\n');
  const pkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', grown.newKey.privateKey)).toString('base64');
  writeFileSync(`${outDir}/${role}-key.b64`, pkcs8 + '\n');
  console.error(`  ✓ ${grown.keylog.length} entries → ${outDir}/ust-keylog`);
  console.error(`  ✓ new ${role} key → ${outDir}/${role}-key.b64  (key_id ${grown.newKey.key_id})`);
  console.error('  ↳ serve the grown log at /.well-known/ust-keylog for a consumer to see it');
}
export async function cmdRotate() {
  const domain = arg('domain');
  if (!domain || domain === true) die('usage: ust rotate --domain <d> --root <encrypted-root.b64> [--key-id <key_id>] [--keylog <served array file>]\n         [--reason retired|compromised [--compromised-since <RFC3339-Z>]] [--out .]\n  APPENDS a key rotation to the served log (never re-mints). Old docs stay valid under the key active at their anchored time (§12.2).\n  --key-id NAMES the key being replaced; it is REQUIRED once more than one operational key is active, and the\n  successor INHERITS that key\'s role. To change what a key is FOR, add one beside it: `ust key add --role`.');
  const rootFile = arg('root'); if (!rootFile || rootFile === true) die('--root <encrypted root backup .b64> required (the cold crown key)');
  // fetch the current identity (genesis + served key-log), or take the log from --keylog
  const get = async (p) => { const r = await fetch(`https://${domain}${p}`, { signal: AbortSignal.timeout(10000), redirect: 'error' }); if (!r.ok) throw new Error(`HTTP ${r.status} at ${p}`); return r.text(); };
  let genesis; try { genesis = JSON.parse(await get('/.well-known/ust-genesis')); } catch (e) { die('cannot fetch genesis for ' + domain + ': ' + (e.message || e)); }
  if (!P.isValid(P.verify(genesis, { context: 'key' }))) die('served genesis does not VERIFY');
  const klFile = arg('keylog', null);
  let keylog;
  try { keylog = (klFile && klFile !== true) ? JSON.parse(readFileSync(klFile, 'utf8')) : JSON.parse(await get('/.well-known/ust-keylog')); }
  catch (e) { die('cannot load the key-log: ' + (e.message || e)); }
  // decrypt the cold root, reconstruct the signer, self-verify it matches the genesis
  // lazy: only the no-tty fallback needs a readline, and creating one EAGERLY is what made the secret echo
  let rl = null;
  const ask = (q) => { rl ??= openReader(createInterface); return rl.question(q); };
  // hand stdin back before asking for a secret. Here askHidden happens to be the FIRST question, so nothing is
  // open yet and this is a no-op — which is the point: the property holds by CONSTRUCTION rather than by the
  // accident of call order, so adding a question above it later cannot silently reintroduce the echo guard's
  // refusal. That is exactly how the genesis ceremony broke.
  rl = closeReader(rl);
  const pass = await askHidden('  🔑 root passphrase: ', ask);
  let rootSigner;
  try { rootSigner = await rootSignerFrom(decryptKey(readFileSync(rootFile, 'utf8').trim(), pass), genesis.state.data.genesis.value.pub); }
  catch (e) { rl?.close(); die(e.message.includes('match') ? e.message : 'decrypt failed — wrong passphrase or corrupt backup'); }
  const reason = arg('reason', null); const cs = arg('compromised-since', null);
  const kid = arg('key-id', null);
  const { ust_id, time } = W.nowFrame();
  let grown;
  try { grown = await rotateKeylog({ genesis, keylog, rootSigner, reason: reason === true ? null : reason, compromisedSince: cs === true ? null : cs, supersedesKeyId: kid === true ? null : kid, time, ustId: ust_id }); }
  catch (e) { rl?.close(); die(e.message); }
  // SELF-CHECK fail-closed: a doc signed by the NEW op key must resolve authoritative under the grown log
  const probe = await W.seal(await W.buildState({ domain_shard: domain, ust_id, key_id: grown.newOp.key_id, class: 'observation' }, time, { r: { kind: 'captured', value: { x: '1' } } }), grown.newOp);
  const res = P.resolveAuthority(probe, { genesis, keylog: grown.keylog, noForkConfirmed: true });
    // rev95 — a ceremony self-check asserts what the ceremony PRESERVES. This asked whether the NAME is
    // authoritative, a property of the world the ceremony neither holds nor should: it supplied only
    // `noForkConfirmed`, which yields `consumer-override` — the value #98 hardened the protocol to withhold so a
    // caller boolean cannot name a canonical. So it died on its own check EVERY time, and rotation is the only
    // recovery from key compromise. F.5e fixes the real invariant: after the grown log the new key is ACTIVE.
    const ks = P.resolveKeys(genesis, grown.keylog);
    const bound = !ks.error && ks.active instanceof Map && ks.active.has(grown.newOp.key_id);
    if (!bound) { rl?.close(); die('self-check FAILED: the new key is NOT in the active set after the grown log (' + (active.error || 'not present') + ')'); }
  rl?.close();
  const outDir = (arg('out', null) && arg('out', null) !== true) ? arg('out', null) : '.';
  writeFileSync(`${outDir}/ust-keylog`, JSON.stringify(grown.keylog, null, 2) + '\n');
  const newOpPkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', grown.newOp.privateKey)).toString('base64');
  writeFileSync(`${outDir}/operational-key.b64`, newOpPkcs8 + '\n');
  console.log('\n  ══════════════════════════════════════════════');
  console.log(`  ✅ KEY ROTATED — ${domain}  (APPENDED, identity unchanged)`);
  console.log('  ══════════════════════════════════════════════');
  console.log(`  key-log        ${keylog.length} → ${grown.keylog.length} entries  (prefix preserved — never rewritten)`);
  console.log(`  new op key     ${grown.newOp.key_id}  (warm daily signer)`);
  if (grown.revokedPub) console.log(`  revoked        old op key, reason=${reason}${reason === 'compromised' ? ' since ' + cs : ''}`);
  console.log('\n  📦 outputs');
  console.log(`  ${outDir}/ust-keylog             → PUBLIC — serve at /.well-known/ust-keylog (the grown array)`);
  console.log(`  ${outDir}/operational-key.b64    → 🔥 WARM — the engine's new signer (an env var), then DELETE the file`);
  console.log('\n  ⏳ validity of OLD documents (§12.2 X1 — decided against ANCHORED time, not now):');
  if (reason === 'compromised') console.log(`     compromised: an old-key doc is VALID only if its anchor proves it existed BEFORE ${cs} (else INVALID, fail-closed).`);
  else if (reason === 'retired') console.log('     retired: an old-key doc is VALID iff its anchor time is at/before this rotation (hygienic — history intact).');
  else console.log('     no revocation: old-key docs remain VALID (the key is superseded, not revoked). Add --reason to revoke.');
  console.log('\n  ▶️  next: serve the grown key-log, then point the engine at the new operational key.');
  console.log(`     one-click reserve: ${invocation()} publish cf --domain ${domain} --genesis <ust-genesis> --keylog ${outDir}/ust-keylog --auth wrangler`);
}

// Run the dispatcher ONLY when executed directly — importing this module (regression suite / Go-binding
// harness) must not trigger the CLI or its process.exit.
// ─── ust cadence — DECLARE or CHANGE the stream grid (§11.3). Same ceremony class as `ust rotate`: the COLD root key
// signs, nothing warm is pulled out of a running engine. Measured before building this: the genesis key is active by
// construction, so resolveCadence accepts its signature — an operator never needs the operational key for this.
// The cadence log is its OWN chain: the first entry chains from the GENESIS content_hash, not from the key-log.
export async function cmdCadence() {
  const domain = arg('domain');
  if (!domain || domain === true) die('usage: ust cadence --domain <d> --root <encrypted-root.b64> --seconds <n> --effective-from <ust:YYYYMMDD.HH[MM[SS]]>\n         [--cadence-log <served array file>] [--out <dir>]   # declare/change the SIGNED stream grid (§11.3)');
  const rootFile = arg('root'); if (!rootFile || rootFile === true) die('--root <encrypted root backup .b64> required (the cold crown key)');
  const secsRaw = arg('seconds'); if (!secsRaw || secsRaw === true) die('--seconds <n> required — the grid spacing in SECONDS');
  const seconds = String(secsRaw);
  if (!/^[1-9][0-9]*$/.test(seconds)) die('--seconds must be a canonical positive integer of seconds (§11.3): "30", never "1.5" or "030"');
  const effFrom = arg('effective-from'); if (!effFrom || effFrom === true) die('--effective-from <ust_id> required — the slot this cadence takes effect at');

  const get = async (p) => { const r = await fetch(`https://${domain}${p}`, { signal: AbortSignal.timeout(10000), redirect: 'error' }); if (!r.ok) { const e = new Error(`HTTP ${r.status} at ${p}`); e.httpStatus = r.status; throw e; } return r.text(); };
  let genesis; try { genesis = JSON.parse(await get('/.well-known/ust-genesis')); } catch (e) { die('cannot fetch genesis for ' + domain + ': ' + (e.message || e)); }
  if (!P.isValid(P.verify(genesis, { context: 'key' }))) die('served genesis does not VERIFY');
  let keylog = [];
  try { keylog = JSON.parse(await get('/.well-known/ust-keylog')); } catch (e) { if (e.httpStatus !== 404 && e.httpStatus !== 410) die('key-log present but unreadable: ' + (e.message || e)); }

  // ABSENT (404/410) is the first declaration; anything else unreadable must NOT be treated as empty — that would chain
  // a new entry onto the wrong head and silently orphan whatever is already served.
  const clFile = arg('cadence-log', null);
  let log = [];
  if (clFile && clFile !== true) { try { log = JSON.parse(readFileSync(clFile, 'utf8')); } catch (e) { die('cannot read --cadence-log: ' + (e.message || e)); } }
  else { try { log = JSON.parse(await get('/.well-known/ust-cadence')); } catch (e) { if (e.httpStatus !== 404 && e.httpStatus !== 410) die('cadence-log present but unreadable — refusing to chain onto an unknown head: ' + (e.message || e)); } }
  if (!Array.isArray(log)) die('the served cadence log is not a JSON array');

  const prev = log.length ? P.contentHash(log[log.length - 1]) : P.contentHash(genesis);
  console.error(`  chaining onto ${log.length ? 'cadence entry #' + (log.length - 1) : 'the GENESIS'} — prev ${prev.slice(0, 22)}…`);

  // lazy: only the no-tty fallback needs a readline, and creating one EAGERLY is what made the secret echo
  let rl = null;
  const ask = (q) => { rl ??= openReader(createInterface); return rl.question(q); };
  // hand stdin back before asking for a secret. Here askHidden happens to be the FIRST question, so nothing is
  // open yet and this is a no-op — which is the point: the property holds by CONSTRUCTION rather than by the
  // accident of call order, so adding a question above it later cannot silently reintroduce the echo guard's
  // refusal. That is exactly how the genesis ceremony broke.
  rl = closeReader(rl);
  const pass = await askHidden('  🔑 root passphrase: ', ask);
  let rootSigner;
  try { rootSigner = await rootSignerFrom(decryptKey(readFileSync(rootFile, 'utf8').trim(), pass), genesis.state.data.genesis.value.pub); }
  catch (e) { rl?.close(); die(e.message.includes('match') ? e.message : 'decrypt failed — wrong passphrase or corrupt backup'); }
  rl?.close();

  const { ust_id, time } = W.nowFrame();
  const entry = await W.seal(P.buildCadenceEntry({ domain_shard: domain, ust_id, key_id: rootSigner.key_id }, time, seconds, effFrom, prev), rootSigner);
  const grown = [...log, entry];

  // SELF-CHECK, fail-closed: the grown log must RESOLVE to this cadence at a moment inside its effect, and must NOT
  // have moved the grid before it. A file that does not resolve is never written — the operator would otherwise publish
  // an entry that no verifier applies.
  const after = P.resolveCadence(genesis, grown, effFrom, { keylog });
  if (after.error) die('self-check FAILED — the grown log does not resolve: ' + after.error + ' ' + (after.detail || ''));
  if (String(after.cadence) !== seconds) die(`self-check FAILED — at ${effFrom} the log resolves to ${after.cadence}, not ${seconds}`);

  const outDir = (arg('out', null) && arg('out', null) !== true) ? arg('out', null) : '.';
  writeFileSync(`${outDir}/ust-cadence`, JSON.stringify(grown, null, 2) + '\n');
  console.error(`  ✓ ${grown.length} entr${grown.length === 1 ? 'y' : 'ies'} → ${outDir}/ust-cadence`);
  console.error(`    cadence ${seconds}s effective from ${effFrom} · entry ${P.contentHash(entry).slice(0, 22)}…`);
  console.error('    serve it at https://' + domain + '/.well-known/ust-cadence (and mirror it, like the genesis and key-log)');
}

const isMain = (() => { try { return process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; } })();
if (isMain) {
  const cmd = process.argv[2];

  const run = { verify: cmdVerify, canon: cmdCanon, genesis: cmdGenesis, key: cmdKey, rotate: cmdRotate, cadence: cmdCadence, discovery: cmdDiscovery, publish: cmdPublish, mirror: cmdMirror, stream: cmdStream, forkchoice: cmdForkChoice, witness: cmdWitness }[cmd];
  if (!run) { const b = banner(); console.error(b + (b ? '' : 'ust — verify machine-readable state\n\n') + "\n  READ & VERDICT — safe, touches nothing\n  ✓ ust verify <file|->        verify a transcript — exit 0 = VALID, 1 = not (--require-anchored demands proven time)\n  ≡ ust canon  <file|->        print canonical bytes + hash — diff another language's implementation against this\n  … ust stream <frames…>       a verdict about a RANGE, not one document: chain · forks · completeness\n                               (--checkpoint is what makes completeness answerable at all)\n  ⑂ ust forkchoice <docs…>     pick the CANONICAL document among candidates for ONE ust_id — the anchor decides,\n                               never the candidates themselves\n  ◇ ust discovery <domain>     probe a domain's serving surface and report an honest verdict — any infrastructure\n\n  CEREMONY — touches your identity, needs the root key\n  ◉ ust genesis --domain <d>   run the HIGH genesis ceremony (add --publish cf for one-click serving)\n  + ust key add --domain <d> --root <enc> --role <data|issuance>   ADD a key BESIDE the current one (never replaces it)\n  ↻ ust rotate  --domain <d> --root <enc>   APPEND a key rotation to the served log\n                               (never re-mints — documents signed by the old key stay valid)\n  ~ ust cadence --domain <d> --root <enc> --seconds <n> --effective-from <slot>\n                               DECLARE the signed grid your stream follows — what completeness is measured against\n\n  PUBLISH — writes to the world\n  ▲ ust publish <cf|self> --domain <d> --genesis <f>   serve an existing genesis: cf deploys the adapter,\n                               self writes the four artifacts for YOUR stack (asked if omitted)\n  ▣ ust mirror <domain>        publish and attest a SECOND-vendor copy, so your identity does not rest\n                               on one provider\n  † ust witness rekor --domain <d>   log the genesis in a public transparency log, so a second published\n                               history cannot go unnoticed\n"); process.exit(cmd ? 1 : 0); }
  run().catch((e) => die(e.message || String(e)));
}
