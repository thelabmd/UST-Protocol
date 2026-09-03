#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// `ust` — the reference CLI. One command hides each ceremony: verify, canon (DX diagnostic), genesis (#37).
// The Go binary (#34) reproduces this surface so `ust` is one static, language-agnostic entrypoint.
//
// The ceremony CORE is exported as pure functions (buildCeremony / checkPublished / cfUpsert / stageSummary /
// encryptKey) so a notary tool is TESTABLE end-to-end without a live network — the 9th-audit regression suite
// (regression.mjs) drives them directly. cmdGenesis is only the readline/network orchestrator around them.
import { createInterface } from 'node:readline/promises';
import { readFileSync, writeFileSync, realpathSync, mkdirSync, unlinkSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createCipheriv, createDecipheriv, scryptSync, randomBytes, createHash, generateKeyPairSync, createPrivateKey, createPublicKey, sign as edsign } from 'node:crypto';
import * as P from 'ust-protocol';
// #43 — ONE seam for this package: every outbound call inherits the label, so a new call site cannot forget it.
const ustFetch = P.labelledFetch('ust-cli', '1.0.0-rc.108');
import { makeSsrfSafeFetch } from 'ust-protocol/ssrf';   // #71 — the SAME Node SSRF guard the MCP uses (resolve→classify→reject private)
import * as W from '@ust-protocol/web-signer';

const arg = (name, def) => { const i = process.argv.indexOf('--' + name); return i > -1 ? (process.argv[i + 1] ?? true) : def; };
const die = (msg) => { console.error('✗ ' + msg); process.exit(1); };
const HEADER = 'UST/1.0; ref=pkg:npm/ust-protocol; web=https://verify.ustprotocol.com/; call=verify(doc,{context:"data"}); hash=domain-separated; trust=resolve-by-name; proves=bytes+key+time';
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
export const NAMES_VALUE_FLAGS = new Set();   // F.5t-a — `ust names` takes paths and no value-flag today; DECLARED empty rather than left unclassified, because the prefix sweep this replaces is exactly how the first value would become a path
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

// WHAT A CHUNK LEAVES BEHIND. MEASURED 2026-08-03 while giving `ust reroot` its second secret — the first command
// in this tool that needs two. On the terminator the raw loop below used to `resolve` and DISCARD the rest of the
// chunk, so a second `askHidden` waited forever for input that had already arrived and been thrown away. Reproduced
// under a pipe AND under a real pty (`script -q /dev/null`), so it is not a piping artifact: it is a race that an
// interactive human hides by typing slowly, and that a paste or a script loses to every time.
//
// CLOSED 2026-08-03 by `fe0bbe42` — cli(#133, #131): `ust reroot` emits the signed half — and the live run
// found three stoppers. In this tree a narration is written in the commit that fixes what it describes, and
// blame places this paragraph there; noted 2026-08-05, appended rather than rewritten.
//
// The comment inside the loop records the PREVIOUS fix at this exact spot — a pasted passphrase arriving as one
// chunk — which taught it to iterate by code point and still left the remainder on the floor. Same line, same
// class, one layer along: a reader that consumes a CHUNK owes back what it did not use.
let HIDDEN_PENDING = '';
export const __resetHiddenPending = () => { HIDDEN_PENDING = ''; };   // tests only: a leftover must not cross a case
export async function askHidden(q, fallbackAsk) {
  // askHidden must own stdin. A readline interface created BEFORE this call takes stdin over and echoes the
  // line ITSELF — its echo wins over this raw-mode loop, so the passphrase appears in plaintext while the code
  // looks correct. Measured 2026-07-27: the owner ran the cadence ceremony and watched the root passphrase print.
  // Every caller now builds its readline LAZILY, and this guard makes a future eager one loud instead of silent.
  if (process.stdin.listenerCount('data') > 0 || process.stdin.listenerCount('keypress') > 0)
    throw new Error('askHidden: another reader owns stdin (a readline interface is open) — it would ECHO the secret. Create the interface lazily, after this call.');
  if (!process.stdin.isTTY) { console.log('  ⚠️  no tty — the passphrase WILL echo'); return fallbackAsk(q); }
  process.stdout.write(q);
  // drain what the PREVIOUS call was handed and did not use, before touching stdin at all
  if (HIDDEN_PENDING) {
    const nl = HIDDEN_PENDING.search(/[\r\n]/);
    if (nl >= 0) {
      const line = HIDDEN_PENDING.slice(0, nl);
      HIDDEN_PENDING = HIDDEN_PENDING.slice(nl + 1).replace(/^\n/, '');   // a CRLF terminator is one break, not two
      process.stdout.write('*'.repeat(line.length) + '\n');
      return line;
    }
  }
  return await new Promise((resolve) => {
    const chars = [...HIDDEN_PENDING];
    HIDDEN_PENDING = '';
    if (chars.length) process.stdout.write('*'.repeat(chars.length));
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
      const text = b.toString('utf8');
      let i = 0;
      for (const c of text) {
        i += c.length;
        if (c === '\r' || c === '\n') {
          // HAND BACK THE REMAINDER. Everything after this terminator belongs to whoever asks next; dropping it is
          // the defect this buffer exists for. A CRLF pair counts as ONE break.
          HIDDEN_PENDING = text.slice(i).replace(/^\n/, '');
          stdin.setRawMode(wasRaw); stdin.removeListener('data', onData); if (wasPaused) stdin.pause(); process.stdout.write('\n'); return resolve(chars.join(''));
        }
        if (c === '\u0003') { stdin.setRawMode(wasRaw); process.stdout.write('\n'); process.exit(130); }
        if (c === '\u007f' || c === '\b') { if (chars.length) { chars.pop(); process.stdout.write('\b \b'); } continue; }
        // A C0 CONTROL is not a character of a passphrase, and accepting one silently is worse than dropping it:
        // the operator sees an asterisk, cannot see WHAT was accepted, and can never reproduce the secret. Measured
        // 2026-08-03 under a pty harness that sends EOT — the first passphrase came back as "\u0004…" and would have
        // encrypted a crown key under a string nobody could type again. Interrupt, backspace and the terminators are
        // handled above; everything else in C0 is ignored, which is why no asterisk is printed for it.
        if (c < ' ') continue;
        chars.push(c); process.stdout.write('*');
      }
    };
    stdin.on('data', onData);
  });
}
//
// CLOSED 2026-07-27 by `1171a08` — fix(cli): the root passphrase ECHOED — a readline interface was opened
// before the hidden prompt. The guard this paragraph explains landed with it; noted 2026-08-05, appended
// rather than rewritten.

// gold IS the hardware tier — one refusal text, used by the core AND the interview (single source).
export const GOLD_REFUSAL = 'gold is a HARDWARE ceremony (pkcs11 / air-gapped signer). This CLI cannot drive one yet and will not pretend — run --profile silver (software root, encrypted backup), then re-root to hardware via a §12.1 supersession when ready.';

export const encryptKey = (pkcs8, pass) => {
  const salt = randomBytes(16), iv = randomBytes(12), key = scryptSync(pass, salt, 32);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(pkcs8), c.final()]);
  return Buffer.concat([salt, iv, c.getAuthTag(), ct]).toString('base64');
};
// inverse of encryptKey — throws (GCM auth) on a wrong passphrase / corrupt backup (never a silent bad key).
// THE FAILURE MUST SAY WHICH. MEASURED 2026-08-03, live: an operator's crown would not decrypt and the message read
// "wrong passphrase or corrupt backup" — two different worlds with two different remedies, and no way to tell them
// apart. A ciphertext this function produced has a KNOWN SHAPE (16-byte salt, 12-byte IV, 16-byte GCM tag, then the
// key), so "is this even one of ours" is answerable WITHOUT the passphrase, and answering it first turns one useless
// message into two useful ones.
//
// CLOSED 2026-08-03 by `5c2542e3` — cli: a ceremony proves the FILE it wrote, not the value it held. In this
// tree a narration is written in the commit that fixes what it describes, and blame places this paragraph
// there; noted 2026-08-05, appended rather than rewritten.
export const decryptKeyShape = (b64) => {
  const t = String(b64 ?? '').trim();
  if (!/^[A-Za-z0-9+/]+=*$/.test(t)) return 'not base64 — this file is not a backup this tool wrote';
  let b; try { b = Buffer.from(t, 'base64'); } catch { return 'base64 does not decode'; }
  if (b.length <= 44) return `only ${b.length} bytes — too short to carry salt+iv+tag+key, so this is not one of our backups`;
  return null;
};
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
export async function dohConfirmTxt({ domain, genHash, fetchImpl = ustFetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), attempts = 6, delayMs = 3000, onAttempt = null }) {
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
export async function cfUpsert({ domain, txt, genHash, token, fetchImpl = ustFetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), onAttempt = null }) {
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
export function buildWitnessLog(genesisText, anchors = null, priorLogText = null, supersession = null) {
  const g = JSON.parse(genesisText);
  let prior = null;
  if (priorLogText != null) {
    try { prior = typeof priorLogText === 'string' ? JSON.parse(priorLogText) : priorLogText; }
    catch { throw new Error('the prior witness log is unparseable — refusing to replace a history that cannot be read'); }
  }
  const r = P.witnessSuccessor(prior, { domain_shard: g.state.id.domain_shard, content_hash: P.contentHash(g), anchors, supersession });
  if (r.error) throw new Error('witness successor refused: ' + r.error);
  return JSON.stringify(r.log);
}

// Log a genesis leaf-root into Sigstore Rekor (a public transparency log) and return the rekor anchor.
// The Rekor entry is signed by an EPHEMERAL key: the witness value is the immutable, timestamped INCLUSION
// of the genesis leaf-root in a public log — NOT the identity of who logged it (that is the genesis's own
// signature, resolved separately). Convention: the artifact is the root's hex string; Rekor stores its
// sha256. Seconds, not Bitcoin's hours.
export async function logToRekor(rootHex, { fetchImpl = ustFetch, api = 'https://rekor.sigstore.dev' } = {}) {
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

// ── The §20 PROFILE is a served surface of a DIFFERENT KIND, and it is kept out of DISCOVERY_ARTIFACTS on purpose.
// The four above are TRANSCRIPTS: signed, content-addressed, attestable by `content_hash` against a value a
// verifier holds independently. The profile is none of those — it is read for the DECLARATIONS it carries, and a
// copy of it has no expected hash to be compared with. Putting it in the same array would hand every consumer of
// that array a member it cannot process the way it processes the rest, which is the flattening F.5p.1 shows to be
// unsound one level down. Two kinds, two sets.
//
// THE ROUTE CARRIES `*`, and the first version of this did not — a live defect, measured 2026-08-03. A CF route
// pattern without a wildcard matches the path and NOT the same path with a query string, so `/.well-known/ust`
// reached the worker while `/.well-known/ust?x=1` fell through to the previous origin and answered with the OLD
// profile. One path, two documents, chosen by a query parameter: the exact §20.1 query-robustness violation this
// tool probes other publishers for.
//
// CLOSED 2026-08-03 by `097e7829` — cli(#135): the profile route had no wildcard, and one path answered with
// two documents. In this tree a narration is written in the commit that fixes what it describes, and blame
// places this paragraph there; noted 2026-08-05, appended rather than rewritten.
//
// The reasoning that produced it confused ROUTING with DISPATCH. A route decides which requests REACH the worker;
// which artifact answers is decided INSIDE, by a table keyed on the whole pathname. So a wildcard cannot make the
// profile answer for a transcript — `ust*` routes them all here, and each pathname still finds its own row.
export const PROFILE_PATH = '/.well-known/ust';
export const PROFILE_ORIGIN = 'loaded (preserved from live when the caller supplies none)';

export function buildWorkerScript(genesisText, keylogText = null, witnessText = null, cadenceText = null, profileText = null) {
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
const PROFILE = ${profileText === null ? 'null' : JSON.stringify(profileText)};
// A TABLE, not a chain of comparisons: a new discovery artifact is a row, and an absent one stays null →
// 404, which is the very distinction \`ust cadence\` reads to tell ABSENT (first declaration) from UNREADABLE.
// The profile row is keyed on the WHOLE pathname like every other row, which is why routing a WILDCARD to this
// worker is safe: a transcript request still finds its own row, and an unknown \`ust…\` path finds none and 404s.
const SERVED = { '/.well-known/ust-genesis': GENESIS, '/.well-known/ust-keylog': KEYLOG, '/.well-known/ust-cadence': CADENCE, '/.well-known/ust-witness': WITNESS, '${PROFILE_PATH}': PROFILE };
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
export function buildWranglerProject({ domain, genesisText, keylogText = null, witnessText = null, cadenceText = null, profileText = null }) {
  // EVERY route carries `*`, the profile's included: without it the same path with a query string does not match
  // and falls through to whatever served it before — one path answering with two different documents.
  const routes = servedArtifacts({ genesisText, keylogText, cadenceText, witnessText })
    .map((a) => `{ pattern = "${domain}/.well-known/ust-${a}*", zone_name = "${domain}" }`);
  if (profileText !== null && profileText !== undefined) routes.push(`{ pattern = "${domain}${PROFILE_PATH}*", zone_name = "${domain}" }`);
  return {
    'worker.mjs': buildWorkerScript(genesisText, keylogText, witnessText, cadenceText, profileText),
    'wrangler.toml': [
      `name = "ust-genesis-${domain.replaceAll('.', '-')}"`,
      'main = "worker.mjs"',
      'compatibility_date = "2026-01-01"',
      'workers_dev = false',
      `routes = [${routes.join(', ')}]`,
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
export async function collectServed({ domain, genesisText, genPath, keylogText = null, witnessFile = null, cadenceFile = null, profileText = null, fetchImpl = ustFetch, log = () => {} }) {
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

  // THE CEREMONY'S OWN WITNESS LOG WINS, when it is already the successor for THIS genesis. MEASURED on the live
  // re-rooting, 2026-08-03: `buildWitnessLog` DERIVES a successor from the served log, and a derivation only knows
  // the fields it was written for — so the `supersession` transcript that F.5z.5 put on the superseded entry was
  // silently dropped, and the set about to be published claimed a supersession with NO SIGNED HALF. That is exactly
  // the half-crossing §12.1 P2 refuses, assembled by the publish path itself.
  //
  // Deriving is right when there is nothing better; a ceremony's output IS better, because it carries what the
  // ceremony proved. It is not trusted blindly: it must be the successor for this genesis AND survive the same
  // no-shrink rule against what is live, which is the test a mirror will apply on the way in.
  let witnessText = null;
  const wFile = witnessFile || (genPath ? genPath.replace(/[^/\\]+$/, 'ust-witness') : null);
  if (wFile) {
    try {
      const mine = JSON.parse(readFileSync(wFile, 'utf8'));
      if (mine?.active === genHash) {
        const shrank = priorLog ? P.witnessNoShrink(JSON.parse(priorLog), mine) : null;
        if (shrank) die(`the witness log at ${wFile} would not survive the no-shrink rule against what is live: ${shrank}`);
        witnessText = JSON.stringify(mine);
        const signed = mine.genesis_log?.filter((e) => e.supersession).length ?? 0;
        log(`  ℹ️  using the ceremony's witness log — ${mine.genesis_log.length} entries, ${signed} carrying a signed supersession`);
      }
    } catch (e) { if (witnessFile) die(`could not read --witness ${wFile}: ${e.message || e}`); }
  }
  // PRESERVE the profile too, for the same reason the witness log is preserved and by the same measurement: a
  // deploy that omits a surface REPLACES it with nothing. The witness case destroyed anchors; this one would
  // silently drop the operator's declarations, and a declaration that vanishes takes its copies out of
  // attestation with it — the exact invisibility #135 exists to close. Absent both here and live ⇒ genuinely
  // not served, which is F.5p's honest floor and stays distinguishable from unreadable.
  let profile = profileText;
  if (profile === null || profile === undefined) {
    try {
      const r = await fetchImpl(`https://${domain}${PROFILE_PATH}`, { signal: AbortSignal.timeout(10000) });
      if (r.ok) { profile = await r.text(); log('  ↻ carrying the live operator profile forward (none supplied)'); }
    } catch { /* unreachable ⇒ nothing to carry; the deploy simply does not serve one */ }
  }
  return { genesisText, keylogText, cadenceText, witnessText: witnessText ?? buildWitnessLog(genesisText, anchors, priorLog), profileText: profile ?? null };
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

export async function wranglerDeploy({ domain, genesisText, keylogText = null, witnessText = null, cadenceText = null, profileText = null, execImpl = null, writeImpl = null }) {
  const { genHash } = validatePublishInputs({ domain, genesisText, keylogText });
  const files = buildWranglerProject({ domain, genesisText, keylogText, witnessText, cadenceText, profileText });
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
export async function cfApexSteps({ domain, token, flipProxy = false, fetchImpl = ustFetch }) {
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
export async function cfPublish({ domain, genesisText, keylogText = null, witnessText = null, cadenceText = null, profileText = null, token, flipProxy = false, fetchImpl = ustFetch }) {
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
  form.append('worker.mjs', new Blob([buildWorkerScript(genesisText, keylogText, witnessText, cadenceText, profileText)], { type: 'application/javascript+module' }), 'worker.mjs');
  const up = await cf(`/accounts/${accountId}/workers/scripts/${script}`, { method: 'PUT', body: form });
  if (!up.success) throw new Error('worker upload failed: ' + (up.errors?.[0]?.message || '?'));

  // 2. route upsert (list → PUT if present, POST if absent — same idempotence as cfUpsert), ONE pass over the
  // set this deploy carries. line-review P0-3 was exactly this drift: the wrangler road created BOTH routes,
  // the API road only the genesis one, so the worker answered a path Cloudflare never routed to it. A loop over
  // `servedArtifacts` cannot drift from the dispatch table `buildWorkerScript` was handed the same inputs for.
  const pattern = `${domain}/.well-known/ust-genesis*`;
  const routes = (await cf(`/zones/${zone.id}/workers/routes`)).result || [];
  const existing = routes.find((r) => r.pattern === pattern);
  // Every pattern carries `*` — see buildWranglerProject: a pattern without one does not match the same path with
  // a query string, and the request then falls through to the previous origin.
  const routeSet = servedArtifacts({ genesisText, keylogText, cadenceText, witnessText }).map((a) => [a, `${domain}/.well-known/ust-${a}*`]);
  if (profileText !== null && profileText !== undefined) routeSet.push(['profile', `${domain}${PROFILE_PATH}*`]);
  for (const [a, p] of routeSet) {
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
export async function attestDiscovery({ domain, mirrors = [], expectHash = null, fetchImpl = ustFetch }) {
  const checks = [];
  // (0) IS DISCOVERY EVEN DEFINED FOR THIS SHARD? The protocol answers with `isPublicDnsShard`, and the answer
  // is the same one the core gives a verifier resolving an UNTRUSTED document — one predicate, so a publisher
  // attesting its own serving learns the same thing a stranger's verifier would, rather than a fetch error.
  // A key-form or private shard is not a serving FAILURE: there is no name to serve under, so §20.1 does not
  // apply. Saying that here is the difference between "your discovery is broken" and "discovery is not the
  // route to you" — and only the second is true.
  if (!P.isPublicDnsShard(domain)) {
    checks.push({ id: 'shard is a public DNS name (§20.1 applies at all)', status: 'fail',
      detail: `${domain} is not a public DNS name — a verifier's discovery refuses it (SSRF floor), so no serving property is attestable. A key-form shard is reached by handing its genesis over, never by /.well-known.` });
    return { hash: null, checks, verdict: verdictOf(checks) };
  }
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

  // (3) query-robustness: a random unrecognized parameter MUST yield byte-identical content — on EVERY surface
  // this publisher serves, not on the genesis alone.
  //
  // MEASURED 2026-08-03, and the reason this is a loop: the probe ran on the genesis only, and the reference
  // operator's own profile was routed with a pattern carrying no wildcard. `/.well-known/ust` reached the worker
  // while `/.well-known/ust?x=1` did not match the route at all and fell through to the previous origin, which
  // answered with a DIFFERENT, older document. One path, two documents, selected by a query parameter — live, on
  // the surface that declares what the others are, and invisible to a check that named one instance where §20.1
  // quantifies over all of them.
//
// CLOSED 2026-08-03 by `097e7829` — cli(#135): the profile route had no wildcard, and one path answered with
// two documents. In this tree a narration is written in the commit that fixes what it describes, and blame
// places this paragraph there; noted 2026-08-05, appended rather than rewritten.
  const PROBE_PATHS = [['genesis', url], ...DISCOVERY_ARTIFACTS.filter((a) => a !== 'genesis').map((a) => [a, `https://${domain}/.well-known/ust-${a}`]), ['profile', `https://${domain}${PROFILE_PATH}`]];
  for (const [name, u] of PROBE_PATHS) {
    const id = `query-robustness · ${name} (cache identity ⊥ unknown query)`;
    try {
      const base = name === 'genesis' ? baseline : await get(u).then((r) => (r.ok ? r.text() : null));
      // A surface that is NOT SERVED has no query-robustness property to leave unchecked. By F.5p an absent
      // undeclared surface is NOT OFFERED — settled, unattestable now and later — while PARTIAL means "attestable
      // tomorrow". Reporting it as an unchecked property would hold every publisher that does not serve an
      // optional surface below ATTESTED forever, which is a verdict about our probe rather than about them.
      if (base === null) { checks.push({ id, informational: true, status: 'skip', detail: 'not served — NOT OFFERED, so there is no property here to attest' }); continue; }
      const rand = `q${randomBytes(6).toString('hex')}=${randomBytes(6).toString('hex')}`;
      const probed = await get(`${u}?${rand}`).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status} on ?query`))));
      if (probed === base) checks.push({ id, status: 'pass', detail: '?' + rand.slice(0, 12) + '… → byte-identical' });
      else checks.push({ id, status: 'fail', detail: 'response VARIES with an unknown query parameter — one path is answering with two different documents (§20.1)' });
    } catch (e) {
      checks.push({ id, status: 'fail', detail: e.message });
    }
  }

  // (0') the §20 OPERATOR PROFILE — normative since rc.1 and, until this round, fetched by nothing. It is what
  // separates the two facts hiding behind one `absent`: a surface this operator does not run (settled) from one
  // that exists and did not answer (a promise not kept). Absent profile = declares nothing, which is the honest
  // floor: every optional surface then reports NOT OFFERED rather than FAILED, and a PRESENT one still attests.
  let declaredSurfaces = new Set();
  let declaredCopies = [];
  try {
    const pr = await get(`https://${domain}/.well-known/ust`);
    if (pr.ok) {
      const prof = JSON.parse(await pr.text());
      // ONE reader of "what does this profile declare" — the core's (#135, F.5p.1). A second implementation here
      // is how the closed half and the tool's idea of it drift, which is the defect this round exists to close.
      const d = P.parseProfile(prof);
      if (d.error) {
        // WHOSE gap is it. A member this reader does not implement is the READER's reach — reporting it as the
        // publisher's failure is the round-165 defect one surface over: a healthy operator declaring something
        // newer would be called broken, and the consumer sent to debug the wrong party. A MALFORMED known member
        // is still the publisher's, and stays a failure.
        if (d.attributed === 'verifier') {
          checks.push({ id: 'operator profile (§20)', informational: true, status: 'skip', detail: `not evaluated: this build does not implement \`declares.${d.unsupported.join('`, `')}\`. The profile is refused rather than partly honoured — a binding member ignored is an obligation nobody checks — but nothing here is a finding about the operator. Upgrade the reader to evaluate it` });
        } else {
        checks.push({ id: 'operator profile (§20)', informational: true, status: 'fail', detail: `${d.error} — ${d.detail}. A profile that is SERVED and cannot be honoured is not an absent one; a verifier must not guess which member it was meant to ignore` });
        }
      } else {
      declaredSurfaces = new Set(d.serves);
      declaredCopies = d.copies;
      const parts = [d.serves.length ? `serves ${d.serves.join('/')}` : null, d.substrates.length ? `substrates ${d.substrates.join('/')}` : null, d.copies.length ? `${d.copies.length} copy locator(s)` : null].filter(Boolean);
      checks.push({ id: 'operator profile (§20)', informational: true, status: 'pass', detail: parts.length ? `declares: ${parts.join(' · ')}` : 'served, declares no optional surface' });
      }
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
  // A copy the PROFILE names is attested without anyone passing a flag (#135). That is the whole point of the
  // declaration: before it, a published copy was invisible to this check and its staleness unmeasurable — the
  // verifier was not being lax, it had nothing to compare. Genesis copies only here; the other artifacts are
  // compared by `ust mirror`, which holds their expected hashes.
  // Consumer-supplied locators are kept SEPARATE and are not replaced by the profile's: a consumer pinning its
  // own copy is checking the publisher, and letting the publisher supply the comparison target would let it name
  // a copy of itself. The union is safe because every copy is judged against `hash`, which comes from neither.
  const profileCopies = declaredCopies.filter((c) => c.artifact === 'genesis').map((c) => c.url);
  const allCopies = [...new Set([...mirrors, ...profileCopies])];
  if (!allCopies.length) checks.push({ id: 'byte-agreement across declared copies (≥1 copy)', status: 'skip', detail: 'the profile names no copy and no --mirror was given — property NOT ATTESTED' });
  const fetched = [];
  for (const m of allCopies) {
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
export async function confirmLive({ domain, genHash, fetchImpl = ustFetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), attempts = 9, delayMs = 20000, onAttempt = null }) {
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
//
// CLOSED 2026-07-28 by `bcbd2df2` — fix(ceremony): declining an optional field aborted the ceremony, and the
// permanent consequences were stated only after they became permanent. In this tree a narration is written
// in the commit that fixes what it describes, and blame places this paragraph there; noted 2026-08-05,
// appended rather than rewritten.
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
export async function attestMirror({ domain, genesisUrls = [], keylogUrls = [], fetchImpl = ustFetch }) {
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
export async function remintProbe({ domain, fetchImpl = ustFetch }) {
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
// ── `ust explain <doc>` — THE LADDER, and who may move each rung (#137, F.5.1 + F.5p.2) ───────────────────────
//
// `ust verify` answers *is this valid for me, now*. This answers the question an integrator actually has: what
// stands between the document and the next rung, and — decisively — whether that thing is THEIRS to move.
//
// ZERO NETWORK, and this is a property rather than a default. Verification is offline (§, first page), so a tool
// that explained the offline property by reaching out would contradict it. Absent inputs are reported as ABSENT;
// nothing is fetched to fill them in. The cost of running this is therefore exactly one file read.
//
// IT GRANTS NOTHING. The verdict printed here is the verdict `verify` returns for the same inputs — pinned by a
// vector. Reading what would raise a document is not a step toward raising it.
async function cmdExplain() {
  const src = process.argv[3];
  if (!src) die('usage: ust explain <file | - for stdin> [--context data|key] [--genesis <file> --keylog <file>] [--trust-root KEYID=PUB]\n  reports the LADDER: where the document sits, and for every input the verifier did not receive, WHO may supply it\n  makes NO network call — an absent input is reported absent, never fetched (verification is offline by construction)');
  const raw = src === '-' ? readFileSync(0) : readFileSync(src);
  let doc; try { doc = decodeInput(raw.toString('utf8')); } catch (e) { die('not a UST blob/base64/json: ' + e.message); }

  const opts = { context: arg('context', null) || contextFor(doc) };
  for (const [flag, key] of [['genesis', 'genesis'], ['keylog', 'keylog'], ['witness', 'noForkEvidence']]) {
    const f = arg(flag, null);
    if (typeof f === 'string') { try { opts[key] = JSON.parse(readFileSync(f, 'utf8')); } catch (e) { die(`--${flag} unreadable: ${e.message}`); } }
  }
  if (arg('no-fork-confirmed', false)) opts.noForkConfirmed = true;
  const tr = arg('trust-root', null);
  if (typeof tr === 'string') opts.trustRoots = Object.fromEntries(tr.split(',').map((p) => p.split('=')));

  const r = P.explainLadder(doc, opts);
  if (r.error) die(`${r.error}: ${r.detail}`);

  console.log(`\n  ${r.verdict}${r.reason ? ' (' + r.reason + ')' : ''}`);
  if (r.detail) console.log(`  ${r.detail}`);

  console.log('\n  WHERE IT SITS');
  if (r.coordinates === null) {
    // F.5p.2 — an axis the relation never reached is NOT an axis that passed. Saying so is the whole point.
    console.log('    · coordinates NOT REACHED — the relation stopped before computing them.');
    console.log('      This is not "fine": nothing was measured on these axes, and a blank must not read as met.');
  } else {
    console.log(`    · identity      ${r.coordinates.identity.strength} / ${r.coordinates.identity.status} (mode ${r.coordinates.identity.mode})`);
    console.log(`    · time          ${r.coordinates.time.strength} / ${r.coordinates.time.status}`);
    console.log(`    · completeness  ${r.coordinates.completeness}`);
  }

  console.log('\n  WHAT THE VERIFIER WAS GIVEN');
  console.log(r.attempted.length ? '    ' + r.attempted.join(', ') : '    nothing — every input below was absent');

  if (r.absent.length) {
    console.log('\n  WHAT IT WAS NOT GIVEN, AND WHOSE IT IS');
    const pub = r.absent.filter((a) => a.party === 'publisher');
    const wit = r.absent.filter((a) => a.party === 'witness');
    const con = r.absent.filter((a) => a.party === 'consumer');
    if (pub.length) {
      console.log('    the PUBLISHER can change the WORLD here — every consumer gains the same:');
      for (const a of pub) console.log(`      · ${a.input}\n        → ${a.hint}`);
    }
    if (wit.length) {
      console.log('    an INDEPENDENT WITNESS only — neither you nor the consumer can produce this, and your own');
      console.log('    attestation carries nothing here:');
      for (const a of wit) console.log(`      · ${a.input}\n        → ${a.hint}`);
    }
    if (con.length) {
      console.log("    the CONSUMER's own faculty — supplying these to your OWN verifier changes nothing for anyone");
      console.log('    else, and invites you to believe a tier no consumer will see (F.5.1a):');
      for (const a of con) console.log(`      · ${a.input}\n        → ${a.hint}`);
    }
  }

  console.log('\n  This report is a function OF the decision relation and never an input to it: the verdict above is');
  console.log('  the one `ust verify` returns for the same inputs. Reading it changes nothing.');
  process.exit(0);
}

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
    for (const pkg of ['@ust-protocol/ots-verify', '@ust-protocol/rekor-verify', '@ust-protocol/rfc6962-verify']) {
      try { const m = await import(pkg); if (m.substrateVerify) plugins.push(m.substrateVerify); if (m.inclusionVerify) incPlugins.push(m.inclusionVerify); } catch { /* absent */ }
    }
    const substrateVerify = plugins.length ? P.combineSubstrates(plugins) : undefined;
    const inclusionVerify = incPlugins.length ? P.combineInclusion(incPlugins) : undefined;   // #95 — same plugins, other question
    // #71 — the discovery target comes from an UNTRUSTED document; the SSRF guard (resolve → reject private IPs)
    // wraps the fetch on the CLI too, not only the MCP. Core's lexical isPublicDnsShard is the floor beneath it.
    const guardedFetch = makeSsrfSafeFetch(async (u, init) => { console.error(`  ⏳ resolving identity from ${new URL(u).origin} … (--offline to skip)`); return ustFetch(u, init); });
    // round-240 — `inclusionVerify` travels in OPTS, and it was assembled two lines up and then dropped: the call
    // took only `substrateVerify`, so a document carrying a valid inclusion proof had its membership left unchecked
    // and its time reported `unproven` while the anchor beneath it was final in Bitcoin. The loss was SILENT — the
    // command still printed HIGH — which is the same shape round 238 fixed one level up, where the page passed the
    // connector as a transport capability and it was ignored there. `forkchoice`, in this same file, passes it.
    // #177 — the consumer's OWN envelope is FORWARDED, not re-listed. This call used to hand-copy seven fields,
    // and a hand-written list falls behind the thing it copies: `disclosures` and `decKeys` were absent, so
    // `r = rd.verdict` below overwrote a verdict that HAD opened the private partitions with one that had not.
    // Silent, and byte-identical output either way. Exactly the shape the comment above describes for the
    // connector in this same call — one argument over, the second time in this line. Spreading `opts` also
    // carries the resource envelope (maxInputBytes / maxSupportedBytes), which the list had dropped too.
    const rd = await P.resolveByDiscovery(doc, { ...opts, offline: !!arg('offline', false), noForkConfirmed: noFork, inclusionVerify },
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
    // §10 privacy — MEASURED 2026-08-31 (#177), CLOSED 2026-08-31 by this block and the forwarded envelope below: verifying the same document with and without
    // `--disclosures`/`--dec-keys` produced BYTE-IDENTICAL output while the core returned `disclosed: []` against
    // `disclosed: ["position","reading"]`. A key-holder could not tell a successful disclosure from having passed
    // no files at all. The line prints what OPENED and, in the same breath, what stayed closed — the negative half
    // is the one a reader cannot reconstruct, since a private partition looks identical either way on the wire.
    {
      const priv = Object.entries((doc && doc.state && doc.state.data) || {}).filter(([, p]) => p && p.privacy);
      if (priv.length) {
        // THREE states, not two (§14.8 per-channel): fully checked · value known but one channel unexamined ·
        // untouched. Collapsing the middle one into either neighbour is the defect this line exists for — calling
        // it `opened` claims a check nobody ran, calling it `closed` denies the reader a value they already hold.
        const opened = new Set(r.disclosed || []);
        const partial = new Map((r.disclosed_partial || []).map((x) => [x.partition, x]));
        const shut = priv.filter(([n]) => !opened.has(n) && !partial.has(n));
        console.log('  private  : ' + priv.length + ' partition(s) — '
          + (opened.size ? 'opened ' + [...opened].join(', ') : 'none opened')
          + (partial.size ? '; PARTIAL ' + [...partial.values()].map((x) => x.partition + ' (value known from the commitment; its ' + x.unchecked + ' channel unchecked — needs key ' + x.needs_key_id + ')').join(', ') : '')
          + (shut.length ? '; still closed ' + shut.map(([n, p]) => n + ' (' + p.privacy + ')').join(', ') : ''));
        if (partial.size) console.log('     a PARTIAL value is bound by the commitment and is genuine — what is unknown is whether the publisher\'s ciphertext says the same, which only the key settles');
        if (shut.length && !opts.disclosures) console.log('     supply --disclosures {partition:{nonce,value}} to open them; the commitment decides, so a wrong pair cannot forge — only fail to reveal');
        if (shut.some(([, p]) => p.privacy === 'encrypted') && !opts.decKeys) console.log('     an encrypted partition also accepts --dec-keys {key_id:key}, which checks the ciphertext AGAINST the commitment (E-COMMIT if they disagree)');
      }
    }
    console.log('  tier     : ' + ['LIGHT', 'HIGH', 'TOP'].map((t) => (t === tier ? `[${t}]` : ` ${t} `)).join('→'));
    if (tier === 'LIGHT' && resolution && !resolution.error && !noFork) {
      console.log('\n  ℹ️  the name RESOLVED (key belongs to its chain, capacity admitted) but stays provisional');
      console.log('     without the no-fork witness. Once you have independently confirmed no rival genesis');
      console.log('     exists, re-run with:  --no-fork-confirmed   → VALID:HIGH');
    } else if (tier === 'LIGHT' && !genesisPath && !resolution) {
      console.log('\n  ✅ this is the EXPECTED result for a lone document — it proves the file is signed and');
      console.log('     intact under the key it carries. HIGH is a property of RESOLUTION, not of the file:');
      console.log(`     ${invocation()} verify <doc> --genesis <ust-genesis> --keylog <ust-keylog-0> --no-fork-confirmed`);
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
// §4.4/§10 — TURN YOUR OWN DATA INTO A SIGNED TRANSCRIPT, private partitions included. Measured 2026-08-31 (#177)
// — CLOSED 2026-09-02 by this command: the CLI had fifteen commands and none of them signed a document. It read,
// it ran ceremonies, it published; a publisher who wanted to emit a transcript wrote JavaScript, always. The
// capability map declared `sign` and `build-transcript` FULL on the strength of `seal` occurring inside ceremony
// internals, which is how the gap survived unnoticed until the probe asked what a user can actually type.
//
// PRIVACY IS DECLARED IN THE DATA, not in a flag. A flag would apply to the document; privacy is a property of a
// PARTITION, and a shard mixing open and closed members is the ordinary case (§10). So the input carries
// `privacy` beside `kind`, exactly as the wire does, and this command is a translator rather than a policy.
//
// THE ENVELOPE IS AN OBLIGATION, NOT AN OPTION. The nonce is generated HERE: it must be fresh, unique, and never
// derived from the value (§10, Z2). A tool that generates it and does not hand it back leaves the publisher
// holding a commitment they can never open — the value is theirs and they can no longer disclose it to anyone.
// So `--disclosures-out` is REQUIRED the moment any partition is private, and refusing without it is the only
// honest default: the alternative is a command that silently destroys what it was asked to protect.
async function cmdSign() {
  const src = process.argv[3];
  const usage = 'usage: ust sign <data.json | - > --key <file> [--pass-stdin] --ust-id <ust:YYYYMMDD.HH> --domain <shard>\n'
    + '                 [--class observation|derivation] [--valid-from <iso> --valid-to <iso>]\n'
    + '                 [--disclosures-out <file>]  [--aead-keys <file>]  [--out <file>]\n\n'
    + '  data.json declares privacy PER PARTITION, exactly as the wire does:\n'
    + '    { "station":  { "kind":"captured", "value": { "name":"Baltic-1" } },\n'
    + '      "position": { "kind":"captured", "privacy":"blinded",   "value": { "lat":"54.71" } },\n'
    + '      "reading":  { "kind":"captured", "privacy":"encrypted", "value": { "kp":"5.8" }, "key_id":"ops-2026-09" } }\n\n'
    + '  A private partition MAKES --disclosures-out mandatory: the nonce is generated here, and a tool that\n'
    + '  keeps it leaves you holding a commitment you can never open.';
  if (!src) die(usage);

  const raw = src === '-' ? readFileSync(0, 'utf8') : readFileSync(String(src), 'utf8');
  const dup = scanDupes(rawTextOf(raw));
  if (dup) die('E-CANON: ' + dup + '  (duplicate members are rejected at the RAW boundary — §6)');
  let data; try { data = JSON.parse(rawTextOf(raw)); } catch (e) { die('not JSON: ' + e.message); }
  if (!data || typeof data !== 'object' || Array.isArray(data)) die('the data file must be an OBJECT of partitions keyed by name');

  const ustId = arg('ust-id', null);
  if (!ustId || ustId === true) die('--ust-id is required — a transcript is ADDRESSED (§8), and this tool will not invent the instant you are describing');
  const keyFile = arg('key', null);
  if (!keyFile || keyFile === true) die('--key <file> is required (the same encrypted key file the ceremonies write)');

  // The signer, read exactly as every ceremony reads one — same file shape, same passphrase prompt, so an
  // operator's existing key works here without a second format to learn.
  let pass = null;
  if (arg('pass-stdin', false)) pass = readFileSync(0, 'utf8').trim();
  else if (!/^[A-Za-z0-9+/]+=*$/.test(readFileSync(String(keyFile), 'utf8').trim())) pass = null;
  const keyRaw = readFileSync(String(keyFile), 'utf8').trim();
  let signer;
  try {
    const bytes = pass ? decryptKey(keyRaw, pass) : Buffer.from(keyRaw, 'base64');
    const b = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    const der = (b.length === 48 && b[0] === 0x30) ? b : Buffer.from(b.toString('utf8').trim(), 'base64');
    const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    const pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
    signer = { priv, pub };
  } catch (e) { die('could not read the signing key from ' + keyFile + ': ' + e.message + (pass ? '' : '  (encrypted? add --pass-stdin)')); }

  // §4.3 — the shard is the publisher's, never this tool's guess. Default to the KEY form, which is
  // self-certifying and needs no genesis; a name-form publisher passes --domain and owns what that claims.
  const domain = (() => { const d = arg('domain', null); return d && d !== true ? String(d) : P.keyId(signer.pub); })();
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const vf = (() => { const v = arg('valid-from', null); return v && v !== true ? String(v) : now; })();
  const vt = (() => { const v = arg('valid-to', null); return v && v !== true ? String(v) : new Date(Date.parse(vf) + 3600_000).toISOString().replace(/\.\d+Z$/, 'Z'); })();
  const cls = (() => { const c = arg('class', null); return c && c !== true ? String(c) : 'observation'; })();
  const ID = { domain_shard: domain, ust_id: String(ustId), key_id: P.keyId(signer.pub), class: cls };
  const T = { generated_at: now, valid_from: vf, valid_to: vt };

  const aeadKeys = (() => {
    const f = arg('aead-keys', null);
    if (!f || f === true) return null;
    try { return JSON.parse(readFileSync(String(f), 'utf8')); } catch (e) { die('could not read --aead-keys ' + f + ': ' + e.message); }
  })();

  // ── translate the declarations into partitions, generating one fresh nonce per private member
  const built = {}, envelope = {};
  for (const [name, decl] of Object.entries(data)) {
    if (!decl || typeof decl !== 'object') die(`partition \`${name}\` is not an object`);
    const kind = decl.kind || 'captured';
    if (decl.privacy === undefined) { built[name] = { kind, value: decl.value }; continue; }
    if (decl.value === undefined) die(`private partition \`${name}\` has no \`value\` — this command commits to a value you supply; it cannot commit to nothing`);
    const nonce = randomBytes(16).toString('base64url');          // §10: freshly random, unique, never value-derived
    if (decl.privacy === 'blinded') {
      built[name] = P.blindPartition(name, decl.value, { domain_shard: ID.domain_shard, ust_id: ID.ust_id, nonce, kind }).partition;
    } else if (decl.privacy === 'encrypted') {
      const kid = decl.key_id;
      if (typeof kid !== 'string' || !kid) die(`encrypted partition \`${name}\` must name a \`key_id\` — §10 leaves key management to you, so this tool will not choose one`);
      const k = aeadKeys && aeadKeys[kid];
      if (!k) die(`no AEAD key for \`${kid}\` — supply --aead-keys {"${kid}":"<base64url 32 bytes>"}. This tool does not GENERATE the key: a key it invented and wrote to disk would be a key you did not choose and cannot rotate (§10, key management is out of protocol scope)`);
      const alg = decl.alg || 'AES-256-GCM';
      built[name] = P.encryptPartition(name, decl.value, { domain_shard: ID.domain_shard, ust_id: ID.ust_id, nonce, key_id: kid, key: k, kind, alg }).partition;
    } else {
      die(`partition \`${name}\` declares privacy \`${decl.privacy}\` — §10 has two modes: blinded, encrypted`);
    }
    envelope[name] = { nonce, value: decl.value };
  }

  const outFile = (() => { const o = arg('disclosures-out', null); return o && o !== true ? String(o) : null; })();
  if (Object.keys(envelope).length && !outFile)
    die(`${Object.keys(envelope).length} private partition(s) and no --disclosures-out.\n`
      + '  The nonce was generated here and is NOT recoverable from the document — without the envelope you would\n'
      + '  hold a commitment you can never open, and could never disclose the value to anyone. Refusing rather than\n'
      + '  writing a document that quietly destroys what it was asked to protect.');

  let doc;
  try { doc = P.seal(P.buildState(ID, T, built), signer.priv, signer.pub); }
  catch (e) { die('could not build the transcript: ' + (e.detail || e.message)); }

  // PROVE IT BEFORE HANDING IT OVER — the ceremonies' own rule (`proveWrittenKey`): a tool verifies what it
  // WROTE, not what it held. Every private partition is re-opened from the envelope this command is about to
  // write, so a mismatch between the two is caught here rather than by the reader who cannot fix it.
  const back = P.verify(doc, { context: 'data', disclosures: envelope, ...(aeadKeys ? { decKeys: aeadKeys } : {}) });
  if (!P.isValid(back)) die('the document this command built does not verify: ' + back.result + ' ' + (back.error || back.reason || '') + (back.detail ? ' — ' + back.detail : ''));
  const owed = Object.keys(envelope);
  const got = new Set([...(back.disclosed || []), ...(back.disclosed_partial || []).map((x) => x.partition)]);
  const missing = owed.filter((n) => !got.has(n));
  if (missing.length) die('the envelope does not open every private partition it should — ' + missing.join(', ') + ' stayed closed against the very pairs just written');

  if (outFile) { writeFileSync(outFile, JSON.stringify(envelope, null, 2) + '\n', { mode: 0o600 }); }
  const docOut = (() => { const o = arg('out', null); return o && o !== true ? String(o) : null; })();
  if (docOut) writeFileSync(docOut, JSON.stringify(doc, null, 2) + '\n');
  else console.log(JSON.stringify(doc, null, 2));

  console.error('\n  ✓ signed ' + Object.keys(built).length + ' partition(s) as ' + ID.ust_id + '  ·  ' + back.result);
  console.error('    content_hash ' + P.contentHash(doc));
  if (outFile) {
    console.error('    disclosures  ' + outFile + '  (mode 0600 — ' + owed.length + ' nonce/value pair(s))');
    console.error('    KEEP IT. The nonces are in that file and nowhere else: lose it and the commitments can never be opened,');
    console.error('    by you or by anyone. It is also what you hand a reader to disclose a partition to them.');
  }
}

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

// ─── ust names <path…> — F.5t-a: point the name rule at YOUR OWN published set ─────────────────────────
// F.5t binds every publisher: an artifact either IS a document of this protocol or does not wear its name.
// The obligation quantifies over `Pub(o)` — everything an operator publishes — and `verify` is a function of
// ONE document, so no consumer can establish it. Until this command, the only implementation of the predicate
// enumerated the protocol's own repository, which means the rule bound operators and shipped its decision
// procedure to none of them. This is that procedure, and it is deliberately OFFLINE: whether a named document
// also VERIFIES is a different question that needs its publisher's genesis, and answering both in one verdict
// would rebuild the conflation F.5t exists to remove.
// EVERY FILE, NOT EVERY `*.json`. Measured on a live mirror the hour this shipped: the three artifacts that ARE
// documents there — `ust-genesis`, `ust-keylog`, `ust-witness` — are served extensionless at their well-known
// paths, so an extension filter walked past the only conforming members of the set and reported on the rest. A
// filter by file name is a directory list wearing a different hat, and this whole theorem is about not sampling
// the set. The one bound kept is a SIZE cap, because a walk must not be turned into an unbounded read by a large
// binary — and it is REPORTED rather than applied silently, the same way §13 refuses an over-budget transport
// input instead of quietly truncating it.
const NAME_SWEEP_MAX_BYTES = 4 << 20;

function collectArtifacts(target, out, budget) {
  if (out.length >= budget.max) return;
  let st; try { st = statSync(target); } catch { budget.unreadable.push(target); return; }
  if (st.isDirectory()) {
    let names; try { names = readdirSync(target); } catch { budget.unreadable.push(target); return; }
    for (const n of names.sort()) collectArtifacts(target.replace(/\/$/, '') + '/' + n, out, budget);
    return;
  }
  if (!st.isFile()) return;
  if (st.size > NAME_SWEEP_MAX_BYTES) { budget.oversize.push(target); return; }
  let raw; try { raw = readFileSync(target, 'utf8'); } catch { budget.unreadable.push(target); return; }
  out.push({ id: target, raw });
}

async function cmdNames() {
  const paths = positionals(process.argv.slice(3), NAMES_VALUE_FLAGS);
  if (!paths.length) die('usage: ust names <dir|file…>   # does anything you publish wear the protocol name without being a document of it? (offline)');
  const budget = { max: 200_000, unreadable: [], oversize: [] };
  const entries = [];
  for (const p of paths) collectArtifacts(p, entries, budget);
  const r = P.nameSetReport(entries);

  console.log(`\n  examined ${r.examined} artifact(s) under ${paths.length} path(s) — ${r.named} wear the protocol name, ${r.documents} of those are documents`);
  if (budget.unreadable.length) console.log(`  ⚠️  ${budget.unreadable.length} path(s) could not be read and are NOT part of the count above — a set you could not enumerate is not a set you have checked`);
  if (budget.oversize.length) console.log(`  ⚠️  ${budget.oversize.length} file(s) exceed ${NAME_SWEEP_MAX_BYTES >> 20} MiB and were NOT read — a resource bound, reported rather than applied silently, and therefore not part of the count above`);
  if (r.violations.length) {
    console.log('');
    for (const v of r.violations.slice(0, 50)) console.log(`  ❌  ${v.id}\n      ${v.why}`);
    if (r.violations.length > 50) console.log(`  …  and ${r.violations.length - 50} more (the count above is complete; this listing is not)`);
  }
  console.log('');
  // FOUR outcomes, never collapsed: examining nothing is the shape a wrong path takes, and reporting it as a
  // pass is how a mirror nobody looked at reads as a clean one.
  if (r.outcome === 'NOTHING_EXAMINED') die('NOTHING EXAMINED — no readable file was found under those paths. This is not a pass; it is a question that was never asked.');
  if (r.outcome === 'VIOLATIONS') die(`${r.violations.length} artifact(s) wear the protocol name without being documents of it (F.5t).\n  A consumer applying the verifier gets E-MALFORMED — the same observation a TRUNCATED or CORRUPTED document produces — so a benign file emits the signal of a broken transfer.\n  Two honest options, and no third: the artifact BECOMES a document of this protocol, or it stops carrying the name. "Carry the name and document the deviation" is not available — the label is read by machines that never read the documentation.`);
  if (r.outcome === 'NONE_WEAR_THE_NAME') console.log('  ✅  nothing under those paths claims the protocol name — no artifact instructs a machine to verify it\n');
  else console.log('  ✅  every artifact claiming the name is shaped as a document of this protocol\n      (this is the NAME question, answered offline; whether each one VERIFIES needs its publisher\'s genesis — `ust verify`)\n');
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
// OWNS ITS OWN READER, like every other secret prompt in this tool. It used to take a caller's `ask`, which meant a
// readline interface was already open on stdin — and `askHidden` refuses that by design, because an open interface
// echoes the line itself. Self-contained here, so the credential cannot be read any other way.
async function resolveDnsToken() {
  const env = process.env.CF_TOKEN || process.env.CLOUDFLARE_API_TOKEN;
  if (env) return env;
  if (!process.stdin.isTTY) throw new Error('no CF token: set CF_TOKEN (Zone.DNS:Edit only) — create one prefilled: ' + CF_DNS_TOKEN_URL);
  let rl = null;
  const ask = (q) => { rl ??= openReader(createInterface); return rl.question(q); };
  rl = closeReader(rl);
  console.log('  no CF_TOKEN — create a DNS-ONLY token (smallest scope; revoke after the ceremony):');
  console.log('  ' + CF_DNS_TOKEN_URL);
  // A CREDENTIAL IS A SECRET, and this prompt ECHOED IT. MEASURED live 2026-08-03, mid-publication: the operator
  // pasted a Cloudflare token and watched it print — into the terminal, into the scrollback, and from there into
  // whatever they copied next. Every other secret in this tool goes through `askHidden`; this one asked with the
  // plain reader because it was written as "just a token" rather than as a secret, which is the whole mistake.
//
// CLOSED 2026-08-03 by `c20967df` — round 160: the fifth axis crossed live — and the eleven minutes it cost
// to learn where the value belongs. In this tree a narration is written in the commit that fixes what it
// describes, and blame places this paragraph there; noted 2026-08-05, appended rather than rewritten.
  //
  // askHidden also fixes the second half of what they saw: a long pasted value arrives as one CHUNK, and the plain
  // reader showed a fragment and appeared to hang. askHidden reads chunks by code point and hands back the remainder.
  const t = (await askHidden('  paste the token here (hidden): ', ask)).trim();
  rl = closeReader(rl);
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
  // The §20 profile rides the same assembly. Supplied ⇒ this deploy serves it; omitted ⇒ collectServed carries
  // the LIVE one forward, because a deploy that omits a surface replaces it with nothing, and the declarations
  // it carries are what put a named copy into attestation at all (#135).
  const profilePath = typeof arg('profile', null) === 'string' ? arg('profile', null) : null;
  let profileText = null;
  if (profilePath) {
    try { profileText = readFileSync(profilePath, 'utf8'); } catch (e) { die('--profile unreadable: ' + e.message); }
    let d; try { d = P.parseProfile(JSON.parse(profileText)); } catch { die('--profile is not JSON'); }
    if (d.error) die(`--profile is refused by the same reader a verifier uses: ${d.error} — ${d.detail}`);
    console.log(`  ✓ profile declares: ${[d.serves.length ? `serves ${d.serves.join('/')}` : null, d.substrates.length ? `substrates ${d.substrates.join('/')}` : null, d.copies.length ? `${d.copies.length} copy locator(s)` : null].filter(Boolean).join(' · ') || 'nothing (the honest floor)'}`);
  }
  const served = await collectServed({ domain, genesisText, genPath, keylogText, profileText,
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
    // The profile's FILE NAME is `ust`, not `ust-profile`: the name here is the served path's last segment, and
    // §20 fixes that segment as `/.well-known/ust`. Deriving it as `ust-${name}` like the transcripts would write
    // a file onto a path no verifier fetches — served, present, and invisible.
    const fileOf = (name) => (name === 'profile' ? 'ust' : 'ust-' + name);
    for (const [name, text] of Object.entries({ ...files, profile: served.profileText })) {
      if (text == null) { console.log(`  ·  ${fileOf(name)}: not available — not written, and it will not be served`); continue; }
      writeFileSync(`${outDir}/${fileOf(name)}`, text);
      console.log(`  ✓ wrote ${outDir}/${fileOf(name)}  (${Buffer.byteLength(text)} B)`);
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
    closeReader(rl);   // hand stdin back BEFORE the credential prompt — askHidden must own it, or the token echoes
    const dnsToken = await resolveDnsToken();
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
  if (!offline) for (const pkg of ['@ust-protocol/ots-verify', '@ust-protocol/rekor-verify', '@ust-protocol/rfc6962-verify']) {
    try { const m = await import(pkg); if (m.substrateVerify) plugins.push(m.substrateVerify); if (m.inclusionVerify) incPlugins.push(m.inclusionVerify); } catch { /* absent */ }
  }
  const substrateVerify = plugins.length ? P.combineSubstrates(plugins) : undefined;
  const inclusionVerify = incPlugins.length ? P.combineInclusion(incPlugins) : undefined;   // #95 — same plugins, other question
  if (!substrateVerify && !offline) console.error('  ℹ️  no substrate plugin installed — anchor-inclusion cannot be checked → INDETERMINATE. `npm i @ust-protocol/ots-verify` to decide.');
  const r = await P.forkChoice(candidates, { ...(genesis ? { genesis } : {}), ...(keylog ? { keylog } : {}), noForkConfirmed: noFork, offline, context: 'data', substrateVerify, inclusionVerify });
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
    let g; try { g = await ustFetch(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.text() : Promise.reject(new Error('canonical genesis unreachable: HTTP ' + r.status)))); } catch (e) { die(e.message); }
    let k = null;
    try { const kr = await ustFetch(`https://${domain}/.well-known/ust-keylog`, { signal: AbortSignal.timeout(10000) }); k = kr.ok ? await kr.text() : null; } catch { k = null; }
    console.log('  ⏳ publishing via YOUR gh CLI (create-or-update, idempotent — this tool holds no credential)…');
        // the WHOLE served set, fetched the same way discovery reads it — a mirror of two of four is a mirror that
    // contradicts itself, and after a supersession it contradicts itself loudly.
    const fetchServed = async (name) => { try { const r = await ustFetch(`https://${domain}/.well-known/ust-${name}`, { signal: AbortSignal.timeout(10000) }); return r.ok ? await r.text() : null; } catch { return null; } };
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
  let genesisText; try { genesisText = await ustFetch(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(10000) }).then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); }); }
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
    const r = await ustFetch(`https://${domain}/.well-known/ust-witness`, { signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      priorWitness = await r.text();
      const wl = JSON.parse(priorWitness);
      const g0 = wl?.genesis_log?.find((x) => x.content_hash === genHash);
      existing = Array.isArray(g0?.anchors) ? g0.anchors : [];
    }
  } catch { /* unreachable ⇒ nothing to merge and nothing to extend */ }
  const merged = [...existing.filter((a) => (a.anchor?.substrate ?? a.substrate) !== 'rekor'), anchor];
  const witness = buildWitnessLog(genesisText, merged, priorWitness);

  // The §20 profile rides this deploy too when supplied; omitted, collectServed carries the live one forward.
  // Without this the anchor deploy would be a second point of no return for a change that belongs in the same one.
  const wp = typeof arg('profile', null) === 'string' ? arg('profile', null) : null;
  let witnessProfile = null;
  if (wp) { try { witnessProfile = readFileSync(wp, 'utf8'); } catch (e) { die('--profile unreadable: ' + e.message); }
    const d = P.parseProfile(JSON.parse(witnessProfile));
    if (d.error) die(`--profile is refused by the same reader a verifier uses: ${d.error} — ${d.detail}`); }
  if (arg('deploy', false)) {
    console.log('  ⏳ updating the live witness endpoint (CF worker)…');
    let keylogText = null; try { keylogText = await ustFetch(`https://${domain}/.well-known/ust-keylog`, { signal: AbortSignal.timeout(8000) }).then((r) => r.ok ? r.text() : null); } catch { /* ok */ }
    try { await wranglerDeploy({ domain, ...(await collectServed({ domain, genesisText, genPath: null, keylogText, profileText: witnessProfile, log: console.log })), witnessText: witness }); } catch (e) { die('deploy failed: ' + e.message + '\n  (the anchor is logged in Rekor; re-run --deploy or update the endpoint by hand)'); }
    console.log('  ✅ witness endpoint updated — verifiers with @ust-protocol/rekor-verify now confirm no-fork automatically');
    console.log(`     re-attest:  ${invocation()} verify <slot>   (install ots-verify + rekor-verify)`);
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
  ensureOutDir(outDir, die);   // AT ENTRY, before the interview and long before the passphrase — see ensureOutDir

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
    try { proveWrittenKey(`${outDir}/operational-key.b64`, op.pub, { label: 'operational key' });
          proveWrittenKey(`${outDir}/genesis-key${pass ? '.enc' : ''}.b64`, root.pub, { pass: pass || null, label: 'crown' }); }
    catch (e) { throw new Error(`WRITTEN-ARTIFACT CHECK FAILED: ${e.message}. The documents are correct; the files are not — nothing has been published, so re-run rather than carry this to cold storage.`); }
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
      else console.log(`  ⚠️  🌐 the _ust TXT is not visible via DoH yet (registrar propagation) — re-attest later:  ${invocation()} discovery ${domain}`);
    }
    // §20.1 probe (3), WARNING-level here: BINDING is fail-closed above; a serving-contract violation is
    // fixable post-hoc without redoing the ceremony. `ust discovery <domain>` re-attests all four anytime.
    try {
      const rand = `q${randomBytes(6).toString('hex')}=${randomBytes(6).toString('hex')}`;
      const baseline = JSON.stringify(liveDoc); void baseline;
      const a = await ustFetch(`https://${domain}/.well-known/ust-genesis`, { signal: AbortSignal.timeout(10000) }).then((r) => r.text());
      const probed = await ustFetch(`https://${domain}/.well-known/ust-genesis?${rand}`, { signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`))));
      if (probed === a) console.log('  ✅ query-robustness probe: an unknown ?query returns byte-identical bytes (§20.1)');
      else console.log(`  ⚠️  §20.1 SERVING: the response VARIES with an unknown query parameter — cache-key amplification is open; fix the cache config, then \`${invocation()} discovery ${domain}\``);
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
  // THE COMPARISON WAS `pub === pub`. MEASURED 2026-08-03, minutes after `ust key check` was written to protect an
  // operator from a mismatched cold backup: the check built its signer from the PRIVATE key and the SUPPLIED public
  // key, then compared `signer.pub` — derived from that same supplied key — against the argument it came from. An
  // identity, true for every input. A backup for a DIFFERENT identity passed, and the command printed the wrong
  // key_id as proof.
//
// CLOSED 2026-08-03 by `274b6bfb` — cli: a binding check that read its own input — pub === pub, true for
// every backup (F.5w). In this tree a narration is written in the commit that fixes what it describes, and
// blame places this paragraph there; noted 2026-08-05, appended rather than rewritten.
  //
  // This is F.5w with a different subject: a predicate has a DOMAIN on which it is non-trivial, and a binding check
  // that reads its own input is outside it. The public key must be DERIVED FROM THE PRIVATE KEY — that derivation is
  // the only thing that can disagree with the genesis, and disagreeing is the entire job.
  //
  // The ceremonies were not exposed by luck alone: each one verifies its output downstream (`resolveKeys` refuses a
  // key-log entry signed by a key the genesis does not name), so a wrong backup failed there instead. `ust key check`
  // has no downstream — the comparison IS its output — so it was the first caller this could actually deceive.
  // TWO SHAPES EXIST IN THE WORLD, and refusing the second would strand a real operator's crown. Every ceremony
  // encrypts the DER bytes; `ust reroot` briefly encrypted the base64 TEXT of them (measured live, 2026-08-03), so a
  // backup written by that build decrypts to ASCII rather than DER. Both are the same key. Detect by shape — DER for
  // a PKCS#8 Ed25519 key is 48 bytes starting 0x30 — and decode the other, rather than making an operator find out
  // that their cold storage holds something no version can read.
//
// CLOSED 2026-08-03 by `5c2542e3` — cli: a ceremony proves the FILE it wrote, not the value it held. In this
// tree a narration is written in the commit that fixes what it describes, and blame places this paragraph
// there; noted 2026-08-05, appended rather than rewritten.
  const bytes = (() => {
    const b = Buffer.isBuffer(pkcs8) ? pkcs8 : Buffer.from(pkcs8);
    if (b.length === 48 && b[0] === 0x30) return b;                        // DER as written by every ceremony
    const txt = b.toString('utf8').trim();
    if (/^[A-Za-z0-9+/]+=*$/.test(txt)) { const d = Buffer.from(txt, 'base64'); if (d.length === 48 && d[0] === 0x30) return d; }
    return b;                                                             // unrecognised: let the import say so
  })();
  const derived = createPublicKey({ key: bytes, format: 'der', type: 'pkcs8' })
    .export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
  if (derived !== rootPubB64url) throw new Error('decrypted root key does NOT match the served genesis pub — wrong backup');
  const priv = await crypto.subtle.importKey('pkcs8', bytes, { name: 'Ed25519' }, false, ['sign']);
  const pubKey = await crypto.subtle.importKey('raw', Buffer.from(derived, 'base64url'), { name: 'Ed25519' }, true, ['verify']);
  return await W.signerFromKeys(priv, pubKey);
}
// Build the grown key-log. Signs the new op key with the ROOT (a current valid key, §12.2), prev-chained;
// optionally revokes the superseded op key with a reason. Refuses to REWRITE (input MUST be a prefix). Pure.
// The `/.well-known/` reader every CEREMONY command needs. MEASURED 2026-08-03: `ust key add` called this by name
// and NOTHING DEFINED IT — the call was written to a helper that was never created, so the command threw
// `ReferenceError: discoveryFetcher is not defined` on its first line of work, and shipped that way in the published
// package for five days. Nothing caught it: the printed-command gate checks that a printed command STRING dispatches,
// never that the function it dispatches to can run. Meanwhile `rotate` and `cadence` each carried their own copy of
// this fetcher — so the defect and the duplication were the same fact, and defining it once fixes both.
//
// `httpStatus` is carried on the thrown error because ABSENT (404/410) and UNREADABLE are different verdicts to a
// caller: a missing cadence log is the first declaration, an unreadable one must never be treated as empty (that
// would chain onto the wrong head and orphan what is served).
const discoveryFetcher = (domain) => async (path) => {
  const r = await ustFetch(`https://${domain}${path}`, { signal: AbortSignal.timeout(10000), redirect: 'error' });
  if (!r.ok) { const e = new Error(`HTTP ${r.status} at ${path}`); e.httpStatus = r.status; throw e; }
  return r.text();
};
// A directory named on the command line is PROVEN WRITABLE AT ENTRY, never discovered at exit. MEASURED on the
// reference operator's live re-rooting, 2026-08-03: the whole ceremony succeeded — twelve acceptance legs green,
// both passphrases typed, a fresh crown minted in memory — and then `writeFileSync` threw ENOENT because `--out`
// named a directory that did not exist. `writeFileSync` does not create parents. The minted identity was discarded
// and the operator had entered two cold-key secrets for nothing.
//
// The rule: a condition checkable at ENTRY must never be discovered at EXIT. Everything in between is work the
// operator cannot get back, and on a ceremony that work is a cold key taken out of storage.
export function ensureOutDir(dir, die_) {
  try { mkdirSync(dir, { recursive: true }); writeFileSync(`${dir}/.ust-write-probe`, ''); unlinkSync(`${dir}/.ust-write-probe`); return dir; }
  catch (e) { return die_(`--out ${dir} is not writable: ${e.message || e}. Checked at entry, so a ceremony never reaches its last line and throws away work you cannot redo.`); }
}
// PROVE A KEY FILE AFTER WRITING IT, while the operator is still here and the fix is still free. Every ceremony's
// self-checks inspect values held in MEMORY; none of them touches a file, and a file is what the operator carries to
// cold storage. MEASURED live 2026-08-03: a crown was written through a path that encoded it differently from every
// other ceremony — it encrypted and decrypted perfectly and then would not parse — and nothing noticed, because
// nothing read it back. The operator found out with the network on and the passphrase no longer in hand.
//
// CLOSED 2026-08-03 by `5c2542e3` — cli: a ceremony proves the FILE it wrote, not the value it held. In this
// tree a narration is written in the commit that fixes what it describes, and blame places this paragraph
// there; noted 2026-08-05, appended rather than rewritten.
//
// The owner's rule when it happened: check it in the tool, right after the ceremony, while the client is still
// offline. `expectedPub` is what the DOCUMENTS say this key must be; anything else means the file is not the key.
export function proveWrittenKey(path, expectedPub, opts = {}) {
  const { pass = null, label = 'key' } = opts;
  const raw = readFileSync(path, 'utf8').trim();
  const bytes = pass ? decryptKey(raw, pass) : Buffer.from(raw, 'base64');
  const b = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const der = (b.length === 48 && b[0] === 0x30) ? b : Buffer.from(b.toString('utf8').trim(), 'base64');
  const got = createPublicKey({ key: der, format: 'der', type: 'pkcs8' })
    .export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
  if (got !== expectedPub) throw new Error(`the ${label} written to ${path} is NOT the key the documents name`);
  return got;
}
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
// ─── §12.1/F.5y RE-ROOTING — the CROSSING, as one testable core (UST#131) ─────────────────────────────────────
//
// F.5y is why this is not a script. A re-rooting is not one event: several structures a publisher runs are ROOTED
// in `contentHash(genesis)`, each must cross the boundary SEPARATELY, and each stale binding is refused on its own
// (key-log/cadence/stream ⇒ E-PREV, witness ⇒ a RIVAL root, authority chain ⇒ E-MALFORMED). The operator ceremony
// this replaces performed exactly one of them — the authority chain — because that is the one the code answered
// when asked which key signs a re-rooting.
//
// Three rules the shape encodes, each of them a measured defect and not a preference:
//
//  1. THE PRE-STATE DECIDES, NOT THE CALLER. What must be crossed is a property of the SERVED identity. So the
//     caller hands over what it READ and never what it INTENDS: an omitted argument is otherwise indistinguishable
//     from an absent structure, which is the whole difference between "nothing to cross" and "forgot to cross".
//     Same rule `addKeylogKey` already follows for `--role`.
//  2. AN UNKNOWN CARRIED FIELD IS A REFUSAL, NEVER A DROP. `cadence` forgotten costs completeness; `max_partitions`
//     forgotten costs E-BOUNDS on the first real slot — both measured on the dry run. Enumerating the fields we
//     know how to carry and refusing the rest means a genesis field added AFTER this code cannot be silently lost
//     by it; the failure lands on whoever adds the field, loudly, instead of on an operator years later.
//  3. ACCEPTANCE IS INDEXED BY THE PRE-STATE (F.5y.3). A self-check over the artifacts PRODUCED cannot observe an
//     axis the ceremony never touched — that is precisely the uncrossed one. So the checks below range over what
//     was observed instantiated BEFORE, and the one axis this command cannot cross (the running writer's stream)
//     is REPORTED as an obligation with the exact `prev` to use, rather than left to be discovered by a consumer.
const GENESIS_CARRIED = ['max_partitions', 'max_transcript_bytes', 'cadence', 'checkpoint_authority', 'recovery'];
const GENESIS_NOT_CARRIED = ['pub', 'role', 'roles'];   // minted anew / restated by this ceremony, deliberately
export async function runRerootCeremony({ domain, genesisA, keylogA, witnessA = null, cadenceLogA = null, caASigner = null, rootASigner = null, roles = null, assign = {}, drop = [], reason = 'planned', time, ustId }) {
  const vA = genesisA?.state?.data?.genesis?.value;
  if (!vA || typeof vA !== 'object') throw new Error('the served genesis has no readable genesis value — refusing to re-root from an identity that cannot be read');
  const unknown = Object.keys(vA).filter((k) => !GENESIS_CARRIED.includes(k) && !GENESIS_NOT_CARRIED.includes(k));
  if (unknown.length) throw new Error(`the served genesis carries field(s) this command does not know how to carry forward: ${unknown.join(', ')}. Refusing rather than dropping them — a re-rooting silently loses whatever it does not restate, and a lost genesis field cannot be added back without a SECOND re-rooting (rule 2 above; §12.1/F.5y).`);

  // WHAT IS INSTANTIATED — read, never asked (F.5y.2). Each entry is an axis that MUST be crossed.
  const hA = P.contentHash(genesisA);
  const declaresCA = !!vA.checkpoint_authority;
  const instantiated = { keylog: true, authority: declaresCA, witness: !!witnessA, cadenceLog: Array.isArray(cadenceLogA) && cadenceLogA.length > 0 };
  if (instantiated.authority && !caASigner) throw new Error('the served genesis DECLARES a checkpoint authority, so the authority chain must cross the boundary with a signed epoch transition — supply the epoch-A checkpoint-authority key. Beginning epoch B\'s chain from nothing IS the silent reset §12.3.2 forbids.');
  if (!instantiated.authority && caASigner) throw new Error('a checkpoint-authority key was supplied but the served genesis declares no checkpoint authority — there is no chain to hand over, and signing a transition from an authority the genesis never named would assert a link no verifier can check.');
  // §12.1: the recovery set is GENESIS-FIXED, so it cannot be changed later without a further re-rooting. Carrying
  // the same cold shards forward keeps the operator's existing custody working; under `compromised` that is exactly
  // the wrong default, because the ceremony is then being run to walk away from a key set. The reason is therefore
  // asked, and refused rather than guessed.
  if (reason !== 'planned' && reason !== 'compromised') throw new Error("reason must be 'planned' or 'compromised' — under `compromised` the epoch-A recovery set is NOT carried forward, so guessing it would silently re-adopt a set the operator is walking away from");
  if (reason === 'compromised' && vA.recovery) throw new Error('reason=compromised, and the served genesis carries a recovery set: this command will not re-mint a recovery quorum for you. Run the genesis ceremony to establish a fresh set, then re-root onto it — a recovery set distributed across places is custody, not a parameter.');

  // §12.1 P2 / F.5z — the SIGNED half. Conjunct (a) is not optional: measured, a domain takeover produces a
  // well-formed successor log with zero signatures from the outgoing publisher, so an unsigned supersession is
  // exactly what a party holding the NAME can write without holding the KEY. The epoch-A ROOT is therefore
  // required, and its absence is a refusal rather than a weaker ceremony.
  if (!rootASigner) throw new Error('re-rooting requires the epoch-A ROOT key: §12.1 P2 makes a supersession authoritative only when it is BOTH signed by the old genesis key AND reflected in the name-binding root, and only the root can produce the signed half (a terminal `reroot` in the outgoing key log). Without it this ceremony would hand over a name it cannot prove it is entitled to hand over.');
  const rootB = await W.generateSigner({ extractable: true });
  const caB = instantiated.authority ? await W.generateSigner({ extractable: true }) : null;
  const genesisB = await W.seal(P.buildGenesis(
    { domain_shard: domain, ust_id: ustId, key_id: rootB.key_id }, time, rootB.pub,
    vA.max_partitions, vA.max_transcript_bytes, vA.cadence,
    caB ? { key_id: caB.key_id, pub: caB.pub } : undefined,
    reason === 'compromised' ? undefined : (vA.recovery ? { keys: vA.recovery.keys, threshold: vA.recovery.threshold } : undefined),
    roles ?? undefined,
  ), rootB);
  const hB = P.contentHash(genesisB);

  // AXIS 1 — the key-log. Every key ACTIVE under epoch A must be accounted for: re-added under B or explicitly
  // dropped. Silence here is the ceremony's single most expensive miss (measured: a forgotten engine key reads as
  // INDETERMINATE(unavailable), which is exactly what a CORRECT ceremony reads as without witness evidence).
  const ksA = P.resolveKeys(genesisA, keylogA);
  if (ksA.error) throw new Error(`the served genesis + key-log do not RESOLVE (${ksA.error}: ${ksA.detail ?? ''}) — refusing to re-root from an identity a consumer cannot resolve either`);
  if (ksA.supersededBy) throw new Error(`this identity has ALREADY been superseded — its key log ends with a reroot naming ${String(ksA.supersededBy).slice(0, 24)}…. Re-root from THAT genesis, not from this one; the log is terminal and admits no further entry.`);
  const carriedKeys = [...ksA.active.entries()].filter(([kid]) => kid !== genesisA.state.id.key_id && !drop.includes(kid));
  const declaresRoles = Array.isArray(roles) && roles.length > 0;
  // THE ONE INPUT THAT IS NOT IN THE PRE-STATE, AND WHY IT IS ASKED. Rule 1 says read rather than ask — but the
  // usual reason to declare roles is that epoch A had NONE, so there is nothing to read: which key is `data` and
  // which is `issuance` is information the operator holds and the served identity does not. Inheritance cannot
  // supply it either (§F.5e.1: `supersedes` PROPAGATES a role and never INTRODUCES one). So it is asked — and every
  // unassigned key is named AT ONCE rather than one per run, because the operator is standing at a cold key.
  const roleOf = (kid) => assign[kid] ?? ksA.roles?.get(kid) ?? null;
  if (declaresRoles) {
    const unassigned = carriedKeys.map(([kid]) => kid).filter((kid) => !roleOf(kid));
    if (unassigned.length) throw new Error(`epoch B DECLARES role separation (${roles.join(', ')}), and ${unassigned.length} carried key(s) have no role to inherit from epoch A. State one for each, or drop the key deliberately:\n` + unassigned.map((k) => `    ${k}`).join('\n'));
    const bad = carriedKeys.map(([kid]) => [kid, roleOf(kid)]).filter(([, r]) => !roles.includes(r));
    if (bad.length) throw new Error(`role(s) outside what epoch B declares (${roles.join(', ')}): ` + bad.map(([k, r]) => `${k.slice(0, 20)}…=${r}`).join(', '));
  } else if (Object.keys(assign).length) throw new Error('key roles were assigned but epoch B declares NO role separation — a `role` on a key-log entry the verifier cannot act on is E-MALFORMED (§12.2/§F.5e.2)');
  let keylogB = [], prev = hB;
  const rebound = [];
  for (const [kid, pub] of carriedKeys) {
    const role = declaresRoles ? roleOf(kid) : null;
    const entry = await W.seal(P.buildKeyLogEntry({ domain_shard: domain, ust_id: ustId, key_id: rootB.key_id }, time,
      { op: 'add', pub, new_key_id: kid, ...(role ? { role } : {}) }, prev), rootB);
    keylogB = [...keylogB, entry]; prev = P.contentHash(entry); rebound.push({ key_id: kid, role });
  }
  if (!keylogB.length) throw new Error('epoch A has no operating key besides its root, so there is nothing to carry into epoch B — run the genesis ceremony instead of a re-rooting');

  // AXIS 2 — the authority chain: epoch A's FINAL checkpoint, the transition signed by A's authority, and B's C₀.
  let finalCheckpointA = null, transition = null, c0B = null;
  if (instantiated.authority) {
    const epochA = P.genesisEpoch(hA), epochB = P.genesisEpoch(hB);
    finalCheckpointA = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({
      domain_shard: domain, genesis_epoch: epochA, sequence: 0, previous_checkpoint: null,
      active_genesis: hA, current_key_id: vA.checkpoint_authority.key_id, keylog: klCommit(keylogA),
    }), caASigner.priv, caASigner.pub);
    const fId = P.authorityCheckpointId(finalCheckpointA);
    transition = P.buildEpochTransition({ domain_shard: domain, from_genesis_epoch: epochA, from_final_checkpoint: fId, from_sequence: '0',
      to_active_genesis: hB, to_genesis_epoch: epochB, to_key_id: caB.key_id, to_pub: caB.pub, to_initial_sequence: '0' }, caASigner.priv, caASigner.pub);
    c0B = P.sealAuthorityCheckpoint(P.buildAuthorityCheckpoint({
      domain_shard: domain, genesis_epoch: epochB, sequence: 0, previous_epoch_final_checkpoint: fId,
      active_genesis: hB, current_key_id: caB.key_id, keylog: klCommit(keylogB),
    }), await pkFromSigner(caB), caB.pub);
  }

  // THE SIGNED HALF, appended to the OUTGOING log and closing it. Built here because `hB` is only known now, and
  // verified through `resolveKeys` before it leaves this function — a ceremony must never emit what it has not
  // checked, and the check is the same one a consumer will run.
  const prevA = keylogA.length ? P.contentHash(keylogA[keylogA.length - 1]) : hA;
  const supersession = await W.seal(P.buildKeyLogEntry({ domain_shard: domain, ust_id: ustId, key_id: rootASigner.key_id }, time, { op: 'reroot', to_genesis: hB }, prevA), rootASigner);
  const keylogAClosed = [...keylogA, supersession];
  const closedCheck = P.resolveKeys(genesisA, keylogAClosed);
  if (closedCheck.error) throw new Error(`the signed supersession does not resolve against the OLD genesis (${closedCheck.error}: ${closedCheck.detail ?? ''}) — refusing to emit a half a consumer would reject`);
  if (closedCheck.supersededBy !== hB) throw new Error('the signed supersession does not name the new genesis — refusing to emit it');

  // AXIS 3 — the witness log. §12.1: supersession ADDS `superseded_by` and a successor entry, never removes. The new
  // genesis carries no anchors: it has not been anchored yet, and claiming otherwise would be the one thing a
  // witness log cannot do honestly.
  let witnessB = null;
  if (instantiated.witness) {
    const succ = P.witnessSuccessor(witnessA, { domain_shard: domain, content_hash: hB, supersession: keylogAClosed });   // F.5z.5 — the log is the COURIER; omission is a refusal at the consumer, never a forgery here
    if (succ.error) throw new Error('witness supersession refused: ' + succ.error);
    witnessB = succ.log;
  }

  // AXIS 4 — the cadence log. Its entries are SIGNED statements about a grid that was in force; re-issuing them
  // under epoch B would restate history the old epoch already owns. So epoch B gets a FRESH log declaring the grid
  // currently in force, effective from this boundary, and epoch A's log keeps its own history under its own genesis.
  let cadenceLogB = null;
  if (instantiated.cadenceLog) {
    const now = P.resolveCadence(genesisA, cadenceLogA, ustId, { keylog: keylogA });
    if (now.error) throw new Error(`the served cadence log does not resolve at ${ustId} (${now.error}) — refusing to guess which grid to carry`);
    cadenceLogB = [await W.seal(P.buildCadenceEntry({ domain_shard: domain, ust_id: ustId, key_id: rootB.key_id }, time, String(now.cadence), ustId, hB), rootB)];
  }

  // the probe is minted HERE because this is where the new root's private key lives; acceptance only reads its verdict.
  let rootProbe = null;
  if (declaresRoles) {
    const doc = await W.seal(await W.buildState({ domain_shard: domain, ust_id: ustId, key_id: rootB.key_id, class: 'observation' }, time, { r: { kind: 'captured', value: { x: '1' } } }), rootB);
    rootProbe = P.verify(doc, { context: 'data', genesis: genesisB, keylog: keylogB });
  }
  return { genesisB, keylogB, keylogAClosed, supersession, witnessB, cadenceLogB, transition, finalCheckpointA, c0B, rootB, caB, hA, hB, rebound, instantiated, reason, rootProbe };
}
/**
 * F.5y.3 — acceptance INDEXED BY THE PRE-STATE. Its arguments are what was observed instantiated BEFORE the
 * crossing, so an axis the ceremony never touched cannot fall outside its range; a self-check over the artifacts
 * produced would range over exactly the wrong set. Returns a list of { axis, ok, detail } — never throws, because
 * an operator holding a cold key needs the whole picture, not the first failure.
 */
export function acceptReroot({ genesisA, keylogA, witnessA, cadenceLogA, out, roles = null, ustId }) {
  const R = [], add = (axis, ok, detail) => R.push({ axis, ok, detail });
  const { genesisB, keylogB, witnessB, cadenceLogB, transition, finalCheckpointA, hA, hB, rebound, instantiated } = out;
  const domain = genesisA.state.id.domain_shard;

  const ks = P.resolveKeys(genesisB, keylogB);
  add('genesis+key-log resolve', !ks.error, ks.error ? `${ks.error}: ${ks.detail ?? ''}` : `${ks.active?.size ?? 0} active key(s)`);
  const declared = genesisB.state?.data?.genesis?.value?.roles ?? null;
  const wanted = Array.isArray(roles) && roles.length ? [...roles].map(String) : null;
  add('declared roles are what was asked', JSON.stringify(declared) === JSON.stringify(wanted), `document carries ${JSON.stringify(declared)}, asked ${JSON.stringify(wanted)}`);
  const missing = rebound.filter((r) => !ks.active?.has(r.key_id));
  add('every carried key is ACTIVE under epoch B', !ks.error && missing.length === 0,
    missing.length ? `NOT bound: ${missing.map((m) => m.key_id.slice(0, 20) + '…').join(', ')}` : rebound.map((r) => r.key_id.slice(0, 14) + '…' + (r.role ? ` (${r.role})` : '')).join(', '));
  const wrongRole = rebound.filter((r) => r.role && (ks.roles?.get(r.key_id) ?? null) !== r.role);
  add('every carried key kept its role', wrongRole.length === 0, wrongRole.length ? wrongRole.map((r) => r.key_id.slice(0, 14) + '…').join(', ') : (wanted ? 'roles preserved from epoch A' : 'no role separation declared'));

  // the PRE-state is untouched by construction: this ceremony writes new files and mutates nothing served, so
  // epoch-A documents keep resolving under epoch A. Asserted rather than simulated — signing a probe would need
  // epoch-A private keys the ceremony does not hold, and a check that cannot fail is worse than a stated invariant.
  const kA = P.resolveKeys(genesisA, keylogA);
  add('epoch A still resolves (its records stay valid)', !kA.error, kA.error ? `${kA.error}: ${kA.detail ?? ''}` : `${kA.active?.size ?? 0} active key(s), untouched`);

  if (instantiated.authority) {
    const v = P.verifyEpochTransition(transition, { domain_shard: domain, from_genesis_epoch: P.genesisEpoch(hA),
      from_final_checkpoint: P.authorityCheckpointId(finalCheckpointA), from_sequence: '0',
      fromAuthority: genesisA.state.data.genesis.value.checkpoint_authority });
    add('authority chain crosses (epoch transition)', !!v.ok, v.ok ? 'signed by epoch A authority, binds the verified destination' : (v.detail ?? v.error ?? 'refused'));
    // the CHAIN verifier, not a field comparison: C\u2080 must VERIFY against the new genesis with the transition as its
    // licence to re-root. Hand-comparing `previous_epoch_final_checkpoint` asserts the one thing the chain verifier
    // already decides, and would pass a C\u2080 whose SIGNATURE is wrong \u2014 the check would aim beside its own claim.
    // the chain must contain BOTH ends: epoch A's final checkpoint AND epoch B's C₀, with the transition keyed by
    // the destination epoch. Verifying C₀ alone takes the genesis-rooted-START branch, where a
    // `previous_epoch_final_checkpoint` is refused outright — the transition is never even consulted.
    const chain = P.verifyAuthorityCheckpointChain([finalCheckpointA, out.c0B], { genesis: genesisA, epochTransitions: { [P.genesisEpoch(hB)]: transition } });
    add('epoch B initial authority checkpoint VERIFIES', !chain.error && chain.result !== 'INVALID',
      chain.error ? `${chain.error}: ${chain.detail ?? ''}` : `C\u2080 sequence ${out.c0B.body?.sequence}, chain ${chain.result ?? 'accepted'}`);
  } else add('authority chain', true, 'not instantiated — the served genesis declares no checkpoint authority, so nothing is owed');

  if (instantiated.witness) {
    const shrank = P.witnessNoShrink(witnessA, witnessB);
    const old = witnessB?.genesis_log?.find((e) => e.content_hash === hA);
    add('name crosses (witness supersession)', shrank === null && old?.superseded_by === hB && witnessB.active === hB,
      shrank ?? (old ? `old root preserved with ${(old.anchors ?? []).length} anchor(s), superseded by the new active` : 'the superseded root is MISSING from the successor log'));
    // THE ONLY LEG THAT ASKS THE CONSUMER'S QUESTION. Everything above inspects what the ceremony produced; this
    // one takes the position of a party holding ONLY the old genesis hash and asks whether continuity is PROVABLE
    // from what will be served. A successor log without the signed half passes every leg above and fails this one.
    const sup = P.resolveSupersession(genesisA, witnessB);
    add('continuity is PROVABLE to a holder of the old genesis', sup.superseded === true && sup.proven === true && sup.to === hB,
      sup.proven ? 'the signed `reroot` verifies against the OLD root key and names this successor' : (sup.detail ?? 'not proven'));
  } else add('name (witness log)', null, 'no witness log is served, so nothing carries the signed half — a consumer holding the old genesis will REFUSE to follow, which is correct and is your choice to change');

  if (instantiated.cadenceLog) {
    const r = P.resolveCadence(genesisB, cadenceLogB, ustId, { keylog: keylogB });
    const was = P.resolveCadence(genesisA, cadenceLogA, ustId, { keylog: keylogA });
    add('grid crosses (cadence log)', !r.error && String(r.cadence) === String(was.cadence), r.error ? `${r.error} ${r.detail ?? ''}` : `${r.cadence}s, unchanged across the boundary`);
  } else add('grid (cadence log)', true, 'not instantiated — the grid is carried in the genesis field, which this ceremony copied');

  // DECLARED vs WORKING, and not a formality: it is the only leg that distinguishes
  // “we declared roles” from “the roles act”. Signed by the NEW ROOT, whose private key this ceremony holds — under
  // a declared regime the root is bound by its own function and must be refused an `observation` class.
  if (out.rootProbe) add('role separation ACTS (root refused a data class)', out.rootProbe.error === 'E-KEY', out.rootProbe.error ? 'E-KEY — the root cannot sign observations' : `NOT refused — got ${out.rootProbe.result}`);
  else add('role separation', true, 'no roles declared — the key set stays undifferentiated, as before');

  // THE AXIS THIS COMMAND CANNOT CROSS. It lives in a running writer, not in a published document, so it is
  // reported as an obligation with the exact value rather than checked. F.5y's corollary: a writer that continues
  // its chain across the boundary is refused E-PREV for every consumer holding the new genesis, while the ceremony
  // reports success — the failure is in production and visible only at the consumer.
  // NAMES THE PLACE, not just the value. MEASURED on the live crossing, 2026-08-03: this printed the hash alone,
  // and the value was read as "write this into the head pointer" — a store that holds a DIFFERENT claim, namely
  // which document was last PUBLISHED. The engine cross-checks that pointer against its object store, saw a hash it
  // had never published, correctly called it a fork and stopped printing for eleven minutes. Twenty-one slots are
  // missing from the grid and cannot be declared after the fact: §11.1 records sit in the chain BETWEEN the last
  // frame before and the first after, and the chain had already closed over the hole.
  //
  // The value was right and the destination was wrong, which is the failure a bare number invites. A line that
  // hands an operator a hash owes them the place it belongs — and, here, the place it does NOT.
  add('stream crossing (YOURS to perform)', null,
    `the WRITER must publish a frame with prev = ${hB}; the head pointer then becomes THAT frame's hash, as a consequence. `
    + 'Do NOT write this value into the head pointer yourself — that store says which document was last PUBLISHED, and a hash '
    + 'the store has never seen reads as a fork and stops the stream.');
  return R;
}
// The authority checkpoint helpers sign with a node KeyObject, not a web-signer. One conversion, named, so the two
// signing worlds meet in exactly one place instead of drifting into two shapes of the same key.
const klCommit = (entries) => { const c = P.buildKeylogCommitment(entries.map((k) => P.contentHash(k))); return { root: c.root, length: c.length, head: c.head }; };
// ^ the commitment builder returns MORE than the checkpoint body admits — `merkle_root`, `headProof`, and `prove`,
// which is a FUNCTION. Handing its whole return to a signed body throws E-CANON at seal time, and every existing
// call site projects `{root,length,head}` by hand. Named once here so this ceremony has one place to be wrong.
async function pkFromSigner(signer) {
  const pkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', signer.privateKey));
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}
// READ-ONLY, and in its own function on purpose: it decrypts a cold backup to answer ONE question and writes
// nothing. Sharing `cmdKey`'s body made it indistinguishable to the entry-check gate from the mutation beside
// it — the gate demanded an output directory of a command that produces no output. A subcommand doing a
// fundamentally different thing is its own function.
export async function cmdKeyCheck() {
    const rootFile = arg('root'); const genFile = arg('genesis'); const caFile = arg('ca-key');
    // TWO cold things come out of a ceremony and both are unproven until asked. The checkpoint-authority key is
    // stored PLAIN (it is not a crown), so it needs no passphrase — but it needs the same question, because the
    // round that will need it is the NEXT re-rooting, and discovering it there is discovering it too late.
    if (caFile && caFile !== true) {
      let genesis; try { genesis = JSON.parse(readFileSync(String(genFile), 'utf8')); } catch (e) { die('cannot read --genesis: ' + (e.message || e)); }
      const want = genesis?.state?.data?.genesis?.value?.checkpoint_authority;
      if (!want) die('that genesis declares NO checkpoint authority — there is nothing for this key to match');
      let derived;
      try { derived = createPublicKey({ key: Buffer.from(readFileSync(String(caFile), 'utf8').trim(), 'base64'), format: 'der', type: 'pkcs8' })
        .export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url'); }
      catch (e) { die('cannot read --ca-key as a PKCS#8 Ed25519 key: ' + (e.message || e)); }
      if (derived !== want.pub) die('this key is NOT the checkpoint authority that genesis declares — wrong file');
      console.log(`\n  ✅ this key IS the checkpoint authority of that genesis`);
      console.log(`     key_id       ${want.key_id}`);
      console.log(`     genesis      ${P.contentHash(genesis)}`);
      console.log('\n  Nothing was written and nothing left this machine.');
      return;
    }
    if (!rootFile || rootFile === true || !genFile || genFile === true)
      die('usage: ust key check --genesis <ust-genesis file> ( --root <encrypted-root.b64> | --ca-key <ca-key.b64> )\n  Asks ONE question of a cold file: does it belong to that identity? --root is the crown (asks a passphrase);\n  --ca-key is the checkpoint authority (stored plain, no passphrase).\n  No network, no writes, and the key is never printed. Run it the day you STORE a backup, not the day you need it.');
    let genesis; try { genesis = JSON.parse(readFileSync(String(genFile), 'utf8')); } catch (e) { die('cannot read --genesis: ' + (e.message || e)); }
    const pub = genesis?.state?.data?.genesis?.value?.pub;
    if (typeof pub !== 'string') die('--genesis is not a genesis transcript (no state.data.genesis.value.pub)');
    let rl = null;
    const ask = (q) => { rl ??= openReader(createInterface); return rl.question(q); };
    rl = closeReader(rl);
    const pass = await askHidden('  🔑 passphrase for this backup: ', ask);
    rl = closeReader(rl);
    let signer;
    try { signer = await rootSignerFrom(decryptKey(readFileSync(String(rootFile), 'utf8').trim(), pass), pub); }
    catch (e) {
      if (String(e.message).includes('match')) die('the backup DECRYPTS but is a DIFFERENT key than this genesis was signed with — right passphrase, wrong file (or the wrong genesis)');
      die(decryptKeyShape(readFileSync(String(rootFile), 'utf8')) ?? 'the file IS a backup this tool wrote, and the passphrase does not open it — so the phrase is wrong, or this is a backup of a DIFFERENT key. Two files named `genesis-key.enc.b64` exist after a re-rooting: the outgoing crown and the new one.');
    }
    console.log(`\n  ✅ this backup IS the root of that genesis`);
    console.log(`     key_id       ${signer.key_id}`);
    console.log(`     genesis      ${P.contentHash(genesis)}`);
    console.log(`     domain_shard ${genesis.state.id.domain_shard}`);
    console.log('\n  Nothing was written and nothing left this machine. Re-run it whenever you move the backup.');
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
  // `check` — PROVE A COLD BACKUP BEFORE YOU NEED IT. An operator holds an encrypted crown and a genesis and, until
  // now, had no way to ask whether they belong together without performing a ceremony. MEASURED on the reference
  // operator's live re-rooting, 2026-08-03: a freshly minted crown went into a password manager and the only way to
  // test it was to run the next mutation and find out. An untested backup is not a backup, and the moment you
  // discover it is the moment you cannot afford to. Reads nothing from the network, writes nothing, prints no key.
  if (sub === 'check') return await cmdKeyCheck();
  if (sub !== 'add') die('usage: ust key add --domain <d> --root <encrypted-root.b64> [--role <data|issuance>] [--keylog <served array file>] [--out .]\n       ust key check --root <encrypted-root.b64> --genesis <ust-genesis file>   # does this backup match that identity?\n  APPENDS a key BESIDE the current one (never replaces it — that is `ust rotate`).\n  --role is REQUIRED if the served genesis DECLARES role separation and REFUSED if it does not: which one is a\n  property of that genesis, not of this command, so it is read from the genesis rather than demanded up front.');
  const domain = arg('domain');
  if (!domain || domain === true) die('--domain <d> required');
  const rootFile = arg('root'); if (!rootFile || rootFile === true) die('--root <encrypted root backup .b64> required (the cold crown key — every key-log mutation is root-signed, §F.5e.3)');
  const outDir = ensureOutDir((arg('out', null) && arg('out', null) !== true) ? String(arg('out', null)) : '.', die);   // AT ENTRY: a ceremony must never mint a key and then fail to write it
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
  writeFileSync(`${outDir}/ust-keylog`, JSON.stringify(grown.keylog, null, 2) + '\n');
  const pkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', grown.newKey.privateKey)).toString('base64');
  writeFileSync(`${outDir}/${role}-key.b64`, pkcs8 + '\n');
  try { proveWrittenKey(`${outDir}/${role}-key.b64`, grown.newKey.pub, { label: `new ${role} key` }); }
  catch (e) { die(`WRITTEN-ARTIFACT CHECK FAILED: ${e.message}. Nothing was published — re-run.`); }
  console.error(`  ✓ ${grown.keylog.length} entries → ${outDir}/ust-keylog`);
  console.error(`  ✓ new ${role} key → ${outDir}/${role}-key.b64  (key_id ${grown.newKey.key_id})`);
  console.error('  ↳ serve the grown log at /.well-known/ust-keylog for a consumer to see it');
}
export async function cmdRotate() {
  const domain = arg('domain');
  if (!domain || domain === true) die('usage: ust rotate --domain <d> --root <encrypted-root.b64> [--key-id <key_id>] [--keylog <served array file>]\n         [--reason retired|compromised [--compromised-since <RFC3339-Z>]] [--out .]\n  APPENDS a key rotation to the served log (never re-mints). Old docs stay valid under the key active at their anchored time (§12.2).\n  --key-id NAMES the key being replaced; it is REQUIRED once more than one operational key is active, and the\n  successor INHERITS that key\'s role. To change what a key is FOR, add one beside it: `ust key add --role`.');
  const rootFile = arg('root'); if (!rootFile || rootFile === true) die('--root <encrypted root backup .b64> required (the cold crown key)');
  const outDir = ensureOutDir((arg('out', null) && arg('out', null) !== true) ? String(arg('out', null)) : '.', die);   // AT ENTRY: a ceremony must never mint a key and then fail to write it
  // fetch the current identity (genesis + served key-log), or take the log from --keylog
  const get = discoveryFetcher(domain);   // one reader for every ceremony command — see its definition for why
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
  writeFileSync(`${outDir}/ust-keylog`, JSON.stringify(grown.keylog, null, 2) + '\n');
  const newOpPkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', grown.newOp.privateKey)).toString('base64');
  writeFileSync(`${outDir}/operational-key.b64`, newOpPkcs8 + '\n');
  try { proveWrittenKey(`${outDir}/operational-key.b64`, grown.newOp.pub, { label: 'new operational key' }); }
  catch (e) { die(`WRITTEN-ARTIFACT CHECK FAILED: ${e.message}. Nothing was published — re-run.`); }
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
  const outDir = ensureOutDir((arg('out', null) && arg('out', null) !== true) ? String(arg('out', null)) : '.', die);   // AT ENTRY: a ceremony must never mint a key and then fail to write it

  const get = discoveryFetcher(domain);   // one reader for every ceremony command — see its definition for why
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

  writeFileSync(`${outDir}/ust-cadence`, JSON.stringify(grown, null, 2) + '\n');
  console.error(`  ✓ ${grown.length} entr${grown.length === 1 ? 'y' : 'ies'} → ${outDir}/ust-cadence`);
  console.error(`    cadence ${seconds}s effective from ${effFrom} · entry ${P.contentHash(entry).slice(0, 22)}…`);
  console.error('    serve it at https://' + domain + '/.well-known/ust-cadence (and mirror it, like the genesis and key-log)');
}

// ─── ust reroot — the CROSSING (§12.1/F.5y, UST#131) ──────────────────────────────────────────────────────────────
// The command stops at ARTIFACTS IN A DIRECTORY. Publication stays a separate step, so the point of no return is one
// place and it is explicit: nothing here is irreversible, and an operator who mistrusts the result deletes a folder.
//
// It does NOT ask for the epoch-A ROOT key, and that is worth saying out loud rather than leaving as an omission the
// operator notices. The implemented protocol signs a re-rooting with epoch A's checkpoint authority (the transition)
// and epoch B's own new root (its genesis and key-log); §12.1 P2 additionally requires the supersession to be
// "signed by the old genesis key", but that conjunct has no wire form and nothing in any implementation emits or
// checks it — tracked as UST-Protocol#133. Until it is determined, this follows what verifiers actually do.
export async function cmdReroot() {
  const domain = arg('domain');
  if (!domain || domain === true) die('usage: ust reroot --domain <d> --root <encrypted epoch-A root .b64> [--ca-key <epoch-A checkpoint-authority key .b64>]\n         [--roles data,issuance] [--assign <key_id>=<role>,…] [--drop <key_id>,…] [--reason planned|compromised]\n         [--out <dir>]\n  DISCONNECTED: --genesis <f> selects an OFFLINE ceremony; then every surface must be supplied (--keylog/--witness/\n         --cadence-log <f>) or DECLARED absent (--no-keylog/--no-witness/--no-cadence-log). Silence is not an assertion.\n  RE-ROOT this identity onto a NEW genesis, crossing every genesis-rooted structure you have instantiated (F.5y):\n  the key-log, the authority chain, the witness log (the NAME), and the cadence log.\n  --root is the OUTGOING crown. §12.1 P2 makes a supersession authoritative only when it is BOTH signed by the old\n  genesis key AND reflected in the name-binding root, and only that key can produce the signed half. What must cross is read from\n  your SERVED identity, never asked — an omitted flag is indistinguishable from an absent structure.\n  Writes artifacts to a directory. It PUBLISHES NOTHING: until you serve them, nothing has happened.\n  The one axis this cannot cross is your running writer — see its printed obligation.');
  const outDir = ensureOutDir((arg('out', null) && arg('out', null) !== true) ? String(arg('out', null)) : '.', die);
  const caFile = arg('ca-key', null);
  const reason = (arg('reason', null) && arg('reason', null) !== true) ? String(arg('reason', null)) : 'planned';
  const rolesArg = arg('roles', null);
  const roles = (rolesArg && rolesArg !== true) ? String(rolesArg).split(',').map((s) => s.trim()).filter(Boolean) : null;
  if (rolesArg && rolesArg !== true && !roles.length) die('--roles was given but parses to nothing — omit it to re-root without declaring role separation; an empty declaration is not a state this protocol has (§12.1)');
  const assign = {};
  const assignArg = arg('assign', null);
  if (assignArg && assignArg !== true) for (const pair of String(assignArg).split(',')) {
    const [k, v] = pair.split('='); if (!k || !v) die(`--assign expects <key_id>=<role> pairs, got "${pair}"`);
    assign[k.trim()] = v.trim();
  }
  const dropArg = arg('drop', null);
  const drop = (dropArg && dropArg !== true) ? String(dropArg).split(',').map((s) => s.trim()).filter(Boolean) : [];

  // THE PRE-STATE. Read from the served surfaces, or from files for a disconnected ceremony — either way it is READ.
  // ONLINE and OFFLINE are DISJOINT, and that is the point. A disconnected ceremony that still reaches for the
  // network cannot tell "this domain serves no witness log" from "this machine has no network" — and those are the
  // difference between an axis that needs no crossing and one silently skipped. Supplying `--genesis <f>` selects
  // offline; every other surface must then be either SUPPLIED or DECLARED ABSENT. Silence is never an assertion:
  // an operator who simply forgets `--witness` would otherwise skip the crossing that carries the NAME.
  const offline = arg('genesis', null) && arg('genesis', null) !== true;
  const get = discoveryFetcher(domain);
  const fileOr = async (flag, path, parse) => {
    const f = arg(flag, null);
    if (f && f !== true) { try { return parse(readFileSync(String(f), 'utf8')); } catch (e) { die(`cannot read --${flag}: ${e.message || e}`); } }
    if (offline) {
      if (arg('no-' + flag, undefined) !== undefined) return null;       // absence DECLARED, not inferred from silence
      die(`offline ceremony (--genesis is a file): the ${flag} surface is neither supplied nor declared absent. Pass --${flag} <file>, or --no-${flag} if this identity truly serves none — on a disconnected machine an unsupplied surface is indistinguishable from an unreachable one, and guessing here silently skips a crossing (F.5y.2).`);
    }
    try { return parse(await get(path)); }
    catch (e) { if (e.httpStatus === 404 || e.httpStatus === 410) return null; die(`${path} is present but unreadable — refusing to re-root from an identity that cannot be read: ${e.message || e}`); }
  };
  // the genesis goes through the SAME reader as the rest — usage offered `--genesis <f>` for a disconnected ceremony
  // and the first draft of this fetched it unconditionally, so the flag was documented and ignored. A flag a command
  // prints and does not honour is the printed-command defect class one layer in: the text is right, the code is not.
  const genesisA = await fileOr('genesis', '/.well-known/ust-genesis', JSON.parse);
  if (!genesisA) die(`no genesis is served at https://${domain}/.well-known/ust-genesis — there is no identity here to re-root`);
  if (!P.isValid(P.verify(genesisA, { context: 'key' }))) die('the served genesis does not VERIFY — refusing to re-root from it');
  const klParsed = await fileOr('keylog', '/.well-known/ust-keylog', (raw) => { const p = parseKeylogRaw(raw); if (p.err) throw new Error(p.err); return p.entries; });
  if (!klParsed) die('no key-log is served — there is nothing to carry into a new epoch; run `ust genesis` instead');
  const witnessA = await fileOr('witness', '/.well-known/ust-witness', JSON.parse);
  const cadenceLogA = await fileOr('cadence-log', '/.well-known/ust-cadence', JSON.parse);
  console.error(`  ↳ instantiated: key-log ${klParsed.length} entr${klParsed.length === 1 ? 'y' : 'ies'} · witness ${witnessA ? witnessA.genesis_log?.length + ' root(s)' : 'ABSENT'} · cadence log ${cadenceLogA ? cadenceLogA.length + ' entr(ies)' : 'ABSENT'} · checkpoint authority ${genesisA.state.data.genesis.value.checkpoint_authority ? 'DECLARED' : 'none'}`);

  // epoch A's checkpoint authority signs the hand-over. Its key must MATCH what the genesis declared — a key that
  // signs a transition from an authority the genesis never named asserts a link no verifier can check.
  let caASigner = null;
  const declaredCA = genesisA.state.data.genesis.value.checkpoint_authority;
  if (declaredCA) {
    if (!caFile || caFile === true) die('the served genesis DECLARES a checkpoint authority, so the authority chain must cross with a signed epoch transition: --ca-key <the checkpoint-authority key from your genesis ceremony>');
    let priv, pub;
    try { priv = createPrivateKey({ key: Buffer.from(readFileSync(String(caFile), 'utf8').trim(), 'base64'), format: 'der', type: 'pkcs8' });
          pub = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url'); }
    catch (e) { die('cannot read --ca-key as a PKCS#8 Ed25519 key: ' + (e.message || e)); }
    if (pub !== declaredCA.pub) die(`--ca-key is NOT the checkpoint authority this genesis declared (${declaredCA.key_id.slice(0, 24)}…) — refusing to sign a hand-over from an authority the identity never named`);
    caASigner = { priv, pub };
  } else if (caFile && caFile !== true) die('--ca-key was given but the served genesis declares no checkpoint authority — there is no chain to hand over');

  // the OUTGOING crown, read the same way every other ceremony reads it. Lazy reader, stdin handed back BEFORE the
  // question — the property holds by CONSTRUCTION here, so a question added above later cannot reintroduce the echo
  // guard's refusal, which is exactly how the genesis ceremony broke once.
  const rootFile = arg('root');
  if (!rootFile || rootFile === true) die('--root <encrypted epoch-A root backup .b64> required — only the OUTGOING root can sign the supersession (§12.1 P2). Without it this ceremony hands over a name it cannot prove it is entitled to hand over.');
  let rl = null;
  const ask = (q) => { rl ??= openReader(createInterface); return rl.question(q); };
  rl = closeReader(rl);
  const passA = await askHidden('  🔑 epoch-A root passphrase: ', ask);
  rl = closeReader(rl);
  let rootASigner;
  try { rootASigner = await rootSignerFrom(decryptKey(readFileSync(String(rootFile), 'utf8').trim(), passA), genesisA.state.data.genesis.value.pub); }
  catch (e) { die(e.message.includes('match') ? e.message : 'decrypt failed — wrong passphrase or corrupt backup'); }

  const { ust_id, time } = W.nowFrame();
  let out; try { out = await runRerootCeremony({ domain, genesisA, keylogA: klParsed, witnessA, cadenceLogA, caASigner, rootASigner, roles, assign, drop, reason, time, ustId: ust_id }); }
  catch (e) { die(e.message); }

  // ACCEPTANCE BEFORE ANY FILE IS WRITTEN. A ceremony that writes what it has not accepted hands the operator an
  // artifact set to publish that no verifier would take — and the whole point of stopping at a directory is that the
  // directory is trustworthy. Every leg is printed, failed or not: an operator at a cold key needs the picture.
  const legs = acceptReroot({ genesisA, keylogA: klParsed, witnessA, cadenceLogA, out, roles, ustId: ust_id });
  console.log('\n  ── acceptance ──');
  for (const l of legs) console.log(`  ${l.ok === null ? '▸' : l.ok ? '✓' : '✗'} ${l.axis.padEnd(46)} ${l.detail}`);
  const failed = legs.filter((l) => l.ok === false);
  if (failed.length) die(`${failed.length} acceptance leg(s) FAILED — nothing was written. Re-run after fixing; no state changed.`);

  // the SECOND secret of this ceremony, asked through the same lazy reader. Stdin is handed back before each
  // question, so neither ask can leave an interface open across the other — the property the genesis ceremony broke.
  rl = closeReader(rl);
  const pass = await askHidden('  🔑 passphrase for the NEW root key (empty = store it unencrypted): ', ask);
  rl = closeReader(rl);
  const wr = (name, data) => writeFileSync(`${outDir}/${name}`, data);
  const secret = (name, data) => writeFileSync(`${outDir}/${name}`, data, { mode: 0o600 });
  const j = (x) => JSON.stringify(x, null, 2) + '\n';
  wr('ust-genesis', j(out.genesisB));
  wr('ust-keylog', j(out.keylogB));
  if (out.witnessB) wr('ust-witness', j(out.witnessB));
  if (out.cadenceLogB) wr('ust-cadence', j(out.cadenceLogB));
  wr('ust-keylog-epoch-a-closed', j(out.keylogAClosed));   // the outgoing log with its terminal `reroot`; kept for your records and mirrors — the transcript a consumer needs travels in ust-witness
  if (out.transition) { wr('epoch-transition.json', j(out.transition)); wr('final-checkpoint-epoch-a.json', j(out.finalCheckpointA)); wr('checkpoint-0-epoch-b.json', j(out.c0B)); }
  // BUFFER, like every other ceremony. MEASURED live 2026-08-03: this passed `.toString('base64')` into `encryptKey`,
  // so the ciphertext carried the TEXT of a base64 string where every reader expects DER bytes. The file encrypts and
  // decrypts perfectly and then fails to parse — the worst shape a backup defect can take, because it looks fine
  // until the day it is needed. The unencrypted branch is the one that wants base64, and it says so there.
//
// CLOSED 2026-08-03 by `5c2542e3` — cli: a ceremony proves the FILE it wrote, not the value it held. In this
// tree a narration is written in the commit that fixes what it describes, and blame places this paragraph
// there; noted 2026-08-05, appended rather than rewritten.
  const rootPkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', out.rootB.privateKey));
  // THE NAME CARRIES THE IDENTITY IT BELONGS TO. MEASURED live, 2026-08-03: a re-rooting puts a NEW crown beside the
  // OUTGOING one, and the ceremony gave both the same name — `genesis-key.enc.b64` in two directories on one volume.
  // The operator files them into cold storage later, BY NAME, and the two are indistinguishable there. Sorting them
  // out afterwards is impossible from the file alone: one is the crown of an identity, the other of its successor,
  // and both decrypt only under their own passphrase. A short prefix of the genesis hash makes the pair self-sorting
  // and matches what `ust key check --genesis` will ask about.
  const crownName = `genesis-key-${out.hB.slice(7, 19)}${pass ? '.enc' : ''}.b64`;
  secret(crownName, (pass ? encryptKey(rootPkcs8, pass) : rootPkcs8.toString('base64')) + '\n');
  const caName = `checkpoint-authority-key-${out.hB.slice(7, 19)}.b64`;
  if (out.caB) secret(caName, Buffer.from(await crypto.subtle.exportKey('pkcs8', out.caB.privateKey)).toString('base64') + '\n');

  // READ BACK WHAT WAS WRITTEN, WHILE THE OPERATOR IS STILL HERE. Every acceptance leg above inspects values held in
  // MEMORY; none of them touches a file. MEASURED live 2026-08-03: the crown was written through a path that encoded
  // it differently from every other ceremony, so the file encrypted and decrypted perfectly and then would not
  // parse — and nothing noticed, because nothing read it. The operator carried it to cold storage, came back with
  // the network on, and found out there.
//
// CLOSED 2026-08-03 by `5c2542e3` — cli: a ceremony proves the FILE it wrote, not the value it held. In this
// tree a narration is written in the commit that fixes what it describes, and blame places this paragraph
// there; noted 2026-08-05, appended rather than rewritten.
  //
  // The rule the owner stated when it happened: check it in the tool, right after the ceremony, while the client is
  // still offline. So: re-read both cold files from disk and prove them USABLE against the genesis just minted. A
  // failure here is free — the passphrase is still in hand and nothing has been published.
  {
    const fail = (m) => die(`WRITTEN-ARTIFACT CHECK FAILED: ${m}\n  The documents are correct; the files are not. Nothing was published, and your passphrase is still in hand — re-run rather than carry this to cold storage.`);
    const v = out.genesisB.state.data.genesis.value;
    try { proveWrittenKey(`${outDir}/${crownName}`, v.pub, { pass: pass || null, label: 'crown' }); }
    catch (e) { fail(e.message); }
    if (out.caB) { try { proveWrittenKey(`${outDir}/${caName}`, v.checkpoint_authority.pub, { label: 'checkpoint-authority key' }); } catch (e) { fail(e.message); } }
    console.log('  ✓ both cold files re-read from disk and proven against the genesis just minted');
  }

  console.log('\n  ══════════════════════════════════════════════');
  console.log(`  ✅ RE-ROOTED — ${domain}   (artifacts only; NOTHING is published)`);
  console.log('  ══════════════════════════════════════════════');
  console.log(`  epoch A   ${out.hA}`);
  console.log(`  epoch B   ${out.hB}`);
  console.log(`  carried   ${out.rebound.map((r) => r.key_id.slice(0, 16) + '…' + (r.role ? ` (${r.role})` : '')).join(', ')}${drop.length ? `   · dropped ${drop.length}` : ''}`);
  console.log(`  recovery  ${reason === 'compromised' ? 'NOT carried (reason=compromised)' : (genesisA.state.data.genesis.value.recovery ? 'carried forward — your existing cold shards still apply' : 'none declared')}`);
  console.log(`\n  📦 ${outDir}/`);
  console.log('     ust-genesis, ust-keylog' + (out.witnessB ? ', ust-witness' : '') + (out.cadenceLogB ? ', ust-cadence' : '') + '  → PUBLIC, serve at /.well-known/');
  console.log('     ust-keylog-epoch-a-closed           → the outgoing log with its TERMINAL `reroot`; for your records and mirrors.');
  console.log('                                          The transcript a consumer needs travels inside ust-witness — that is the courier.');
  if (out.transition) console.log('     epoch-transition.json, final-checkpoint-epoch-a.json, checkpoint-0-epoch-b.json  → the authority hand-over');
  console.log(`     ${crownName}${pass ? '' : '   ⚠️ UNENCRYPTED'}   → 🧊 COLD — the NEW crown; every key-log mutation needs it.`);
  console.log('       The name carries the genesis it belongs to, so it cannot be confused with the outgoing crown in storage.');
  if (out.caB) console.log(`     checkpoint-authority-key-${out.hB.slice(7, 19)}.b64  → 🧊 COLD — signs epoch B authority checkpoints`);
  console.log('\n  ▶️  the axis this command CANNOT cross — your running writer:');
  console.log(`     the FIRST frame your writer PUBLISHES after the boundary must set  prev = ${out.hB}`);
  console.log('     a writer that keeps chaining frame-to-frame is refused E-PREV by every consumer holding the new');
  console.log('     genesis, while this ceremony reports success. This is a change in the WRITER, not a value to');
  console.log('     paste anywhere: a head pointer or last-published record says which document you PUBLISHED, and a');
  console.log('     hash it has never seen reads as a fork. Measured 2026-08-03 — eleven minutes of stopped stream');
  console.log('     and twenty-one slots that can no longer be declared.');
  console.log('\n  ▶️  then publish — the ONE irreversible step:');
  console.log(`     ${invocation()} publish self --domain ${domain} --genesis ${outDir}/ust-genesis`);
  console.log('     expect the witness to read `pending` until the new genesis is anchored. That is not a failure,');
  console.log('     and re-running the ceremony because of it is how a second genesis gets minted.');
}

// CLOSED 2026-08-03 by `c20967df` — round 160: the fifth axis crossed live — and the eleven minutes it cost
// to learn where the value belongs. In this tree a narration is written in the commit that fixes what it
// describes, and blame places this paragraph there; noted 2026-08-05, appended rather than rewritten.

const isMain = (() => { try { return process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; } })();
if (isMain) {
  const cmd = process.argv[2];

  const run = { verify: cmdVerify, sign: cmdSign, explain: cmdExplain, canon: cmdCanon, names: cmdNames, genesis: cmdGenesis, key: cmdKey, rotate: cmdRotate, cadence: cmdCadence, reroot: cmdReroot, discovery: cmdDiscovery, publish: cmdPublish, mirror: cmdMirror, stream: cmdStream, forkchoice: cmdForkChoice, witness: cmdWitness }[cmd];
  if (!run) { const b = banner(); console.error(b + (b ? '' : 'ust — verify machine-readable state\n\n') + "\n  READ & VERDICT — safe, touches nothing\n  ✓ ust verify <file|->        verify a transcript — exit 0 = VALID, 1 = not (--require-anchored demands proven time)\n  ≡ ust canon  <file|->        print canonical bytes + hash — diff another language's implementation against this\n  … ust stream <frames…>       a verdict about a RANGE, not one document: chain · forks · completeness\n                               (--checkpoint is what makes completeness answerable at all)\n  ⑂ ust forkchoice <docs…>     pick the CANONICAL document among candidates for ONE ust_id — the anchor decides,\n                               never the candidates themselves\n  ◇ ust discovery <domain>     probe a domain's serving surface and report an honest verdict — any infrastructure\n  ⌗ ust names <dir|file…>      point the NAME rule at YOUR OWN published set: an artifact either IS a document\n                               of this protocol or does not wear its name (offline; F.5t)\n\n  CEREMONY — touches your identity, needs the root key\n  ◉ ust genesis --domain <d>   run the HIGH genesis ceremony (add --publish cf for one-click serving)\n  + ust key add --domain <d> --root <enc> --role <data|issuance>   ADD a key BESIDE the current one (never replaces it)\n  ↻ ust rotate  --domain <d> --root <enc>   APPEND a key rotation to the served log\n                               (never re-mints — documents signed by the old key stay valid)\n  ~ ust cadence --domain <d> --root <enc> --seconds <n> --effective-from <slot>\n                               DECLARE the signed grid your stream follows — what completeness is measured against\n  ⟳ ust reroot  --domain <d> --ca-key <enc>   RE-ROOT onto a new genesis, crossing EVERY genesis-rooted\n                               structure you run — key-log, authority chain, witness log (the NAME), cadence.\n                               Writes artifacts; publishes nothing. Your writer must cross the last axis itself.\n\n  PUBLISH — writes to the world\n  ▲ ust publish <cf|self> --domain <d> --genesis <f>   serve an existing genesis: cf deploys the adapter,\n                               self writes the four artifacts for YOUR stack (asked if omitted)\n  ▣ ust mirror <domain>        publish and attest a SECOND-vendor copy, so your identity does not rest\n                               on one provider\n  † ust witness rekor --domain <d>   log the genesis in a public transparency log, so a second published\n                               history cannot go unnoticed\n"); process.exit(cmd ? 1 : 0); }
  run().catch((e) => die(e.message || String(e)));
}
