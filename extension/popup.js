// SPDX-License-Identifier: Apache-2.0
// LITERAL copy of the Pages verifier script (docs/index.html) + two extension extras at the bottom
// (identity display, context-menu handoff). Regenerate by re-running the mirror step — do not hand-edit the copy.

import { verify } from './lib/ust-verify.mjs';
import * as W from './lib/ust-web-signer.mjs';

const $ = (id) => document.getElementById(id);
const inEl = $('in'), outEl = $('out');
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));

function b64decodeUtf8(b64) {
  const bin = atob(b64.replace(/\s+/g, ''));
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

// Accept: full blob (header + ———UST(base64)——— + base64), bare base64, or raw JSON.
function extractDoc(input) {
  let s = input.trim();
  const marker = '———UST(base64)———';
  if (s.includes(marker)) s = s.slice(s.lastIndexOf(marker) + marker.length).trim();
  if (s.startsWith('{')) return JSON.parse(s);
  return JSON.parse(b64decodeUtf8(s));
}

// Human view REGENERATED from the signed document (never the sender's preamble).
// DISPLAY-ONLY markdown: the signed bytes are untouched — the toggle re-renders the SAME string. Escape-first:
// nothing from the document reaches the DOM unescaped; links restricted to http(s); no images are fetched
// (an untrusted document must not make this page load remote resources); no raw HTML passthrough.
const partVals = [];
function mdSafe(src) {
  let t = esc(src);
  t = t.replace(/```([\s\S]*?)```/g, (m, code) => '<pre>' + code.replace(/^\n|\n$/g, '') + '</pre>');
  t = t.replace(/^######\s?(.+)$/gm, '<h4>$1</h4>').replace(/^#####\s?(.+)$/gm, '<h4>$1</h4>')
       .replace(/^####\s?(.+)$/gm, '<h4>$1</h4>').replace(/^###\s?(.+)$/gm, '<h3>$1</h3>')
       .replace(/^##\s?(.+)$/gm, '<h2>$1</h2>').replace(/^#\s?(.+)$/gm, '<h1>$1</h1>');
  t = t.replace(/^(?:---|\*\*\*)\s*$/gm, '<hr>');
  t = t.replace(/^&gt;\s?(.+)$/gm, '<blockquote>$1</blockquote>');
  t = t.replace(/`([^`\n]+)`/g, '<code>$1</code>');
  t = t.replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>').replace(/\*([^*\n]+)\*/g, '<i>$1</i>');
  t = t.replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g, '<a href="$2" rel="noopener nofollow" target="_blank">$1</a>');
  t = t.replace(/^[-*]\s+(.+)$/gm, '<li>$1</li>');
  t = t.replace(/(?:<li>[\s\S]*?<\/li>\n?)+/g, (m) => '<ul>' + m + '</ul>');
  t = t.split(/\n{2,}/).map((b) => /^\s*<(?:h\d|ul|pre|blockquote|hr)/.test(b.trim()) ? b : (b.trim() ? '<p>' + b.replace(/\n/g, '<br>') + '</p>' : '')).join('');
  return t;
}
// A structured value renders as a reader card: string fields become serif prose (markdown-safe), everything
// else stays JSON code. Same escape-first discipline — display-only, the verified bytes never change.
function objectMd(v) {
  return Object.entries(v).map(([k, val]) => {
    if (typeof val === 'string') {
      const rich = val.length > 80 || /[\n#*`]/.test(val);
      const looksId = /^(sha256:|ust:|https?:)/.test(val) && !/\s/.test(val);
      const body = looksId ? `<span class="fv mono">${esc(val)}</span>`
        : rich ? `<div class="fv md">${mdSafe(val)}</div>` : `<span class="fv">${esc(val)}</span>`;
      return `<div class="fld"><span class="fk">${esc(k)}</span>${body}</div>`;
    }
    return `<div class="fld"><span class="fk">${esc(k)}</span><pre style="margin:0">${esc(JSON.stringify(val, null, 2))}</pre></div>`;
  }).join('');
}
function rawOf(entry) { return entry.kind === 'text' ? entry.v : JSON.stringify(entry.v, null, 2); }
function mdOf(entry) { return entry.kind === 'text' ? mdSafe(entry.v) : objectMd(entry.v); }
function renderContent(data) {
  partVals.length = 0;
  const parts = Object.entries(data || {}).map(([name, part]) => {
    if (part && part.value !== undefined) {
      const v = part.value;
      const isText = v && typeof v === 'object' && typeof v.text === 'string';
      const isObj = !isText && v && typeof v === 'object' && !Array.isArray(v);
      const entry = isText ? { kind: 'text', v: v.text } : { kind: isObj ? 'obj' : 'text', v: isObj ? v : JSON.stringify(v, null, 2) };
      const i = partVals.push(entry) - 1;
      const toggle = (isText || isObj)
        ? `<span class="viewtoggle" data-ci="${i}"><button class="vt on" data-mode="md">md</button><button class="vt" data-mode="raw">raw</button></span>`
        : '';
      return `<div class="pblock"><div class="phead"><span class="plabel">${esc(name)}${part.kind ? ' · ' + esc(part.kind) : ''}</span>${toggle}</div><div class="content mdview md" data-ci="${i}">${mdOf(entry)}</div></div>`;
    }
    return `<div class="pblock"><div class="phead"><span class="plabel">${esc(name)} · ${esc(part && part.privacy || 'private')}</span></div><div class="content">${esc(part && part.commit || '(private — committed, not revealed)')}</div></div>`;
  });
  return parts.join('');
}
// raw ⇄ md toggle (display-only; the verified bytes never change)
outEl.addEventListener('click', (e) => {
  const btn = e.target.closest('.vt');
  if (!btn) return;
  const wrap = btn.closest('.viewtoggle');
  const ci = wrap.dataset.ci;
  const box = outEl.querySelector(`.content[data-ci="${ci}"]`);
  if (!box) return;
  wrap.querySelectorAll('.vt').forEach((b) => b.classList.toggle('on', b === btn));
  if (btn.dataset.mode === 'md') { box.classList.add('mdview', 'md'); box.innerHTML = mdOf(partVals[ci]); }
  else { box.classList.remove('mdview', 'md'); box.innerHTML = esc(rawOf(partVals[ci])); }
});

function run() {
  const raw = inEl.value.trim();
  outEl.innerHTML = '';
  if (!raw) return;

  let doc;
  try { doc = extractDoc(raw); }
  catch (e) { outEl.innerHTML = `<div class="verdict bad"><span class="dot"></span>UNREADABLE</div><div class="err">Could not decode a UST document from that input (${esc(e.message)}). Paste the whole blob, the base64, or the JSON.</div>`; return; }

  verify(doc, { context: 'data' }).then((r) => {
    const valid = typeof r.result === 'string' && r.result.slice(0, 6) === 'VALID:';
    const indet = r.result === 'INDETERMINATE';
    const cls = valid ? 'ok' : indet ? 'wait' : 'bad';
    const st = doc.state || {};
    const id = st.id || {};

    let html = `<div class="verdict ${cls}"><span class="dot"></span>${esc(r.result || 'INVALID')}</div>`;

    if (valid) {
      html += `<div class="card"><h2>What the signature proves</h2>${renderContent(st.data)}
        <dl class="kv" style="margin-top:14px">
          <dt>signing key</dt><dd>${esc(id.key_id || r.publisher_claimed || '')}</dd>
          <dt>capture time</dt><dd>${esc(st.time && st.time.generated_at || '')}</dd>
          <dt>frame (ust_id)</dt><dd>${esc(id.ust_id || '')}</dd>
          <dt>class</dt><dd>${esc(id.class || '')}</dd>
        </dl>
        <div class="tierfoot">
          <p class="tierwhy">Why this is <b>LIGHT</b> — the floor tier, decided from the document alone:</p>
          <div class="tierlists">
            <div>
              <p class="cap">Proven</p>
              <ul class="proved">
                <li>the exact bytes above — unaltered since signing</li>
                <li>the signing key — the identity <em>is</em> this key</li>
                <li>the claimed capture time, as the publisher wrote it</li>
              </ul>
            </div>
            <div>
              <p class="cap">Not proven</p>
              <ul class="notproved">
                <li>who the publisher is — a verified <em>name</em> is HIGH (genesis + key log)</li>
                <li>independently proven time — an anchor is TOP</li>
                <li>where the bytes came from — a &ldquo;Source:&rdquo; line is the sender&rsquo;s unverified claim</li>
              </ul>
            </div>
          </div>
        </div></div>`;
    } else if (indet) {
      html += `<p class="note">The verifier <b>cannot decide</b> at the requested tier — information it needs
        (e.g. an anchor or a name-authority witness) was not available. This is <b>not</b> INVALID; it is an honest
        "cannot confirm." ${r.reason ? '<br>Reason: <code>' + esc(r.reason) + '</code>' : ''}</p>`;
    } else {
      html += `<div class="err">${esc(r.error || 'INVALID')}${r.detail ? ' — ' + esc(r.detail) : ''}</div>
        <p class="note">The document did <b>not</b> verify: its bytes, hashes, or signature are inconsistent. A
        genuine UST that was edited in transit fails exactly here.</p>`;
    }
    outEl.innerHTML = html;
  }).catch((e) => {
    outEl.innerHTML = `<div class="verdict bad"><span class="dot"></span>ERROR</div><div class="err">${esc(e.message || String(e))}</div>`;
  });
}

$('go').addEventListener('click', run);
$('clear').addEventListener('click', () => { inEl.value = ''; outEl.innerHTML = ''; inEl.focus(); });
inEl.addEventListener('input', () => { if (inEl.value.trim()) run(); else outEl.innerHTML = ''; });

// ── extension extras (the ONLY additions to the page script) ──────────────────────────────────────────
function openDB() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('ust-signer', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('keys');
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
const idbGet = (key) => openDB().then((db) => new Promise((res) => {
  const t = db.transaction('keys').objectStore('keys').get(key);
  t.onsuccess = () => res(t.result ?? null); t.onerror = () => res(null);
}));
(async () => {
  const stored = await idbGet('ed25519');
  if (!stored?.publicKey) {
    document.getElementById('id').textContent = 'no identity yet — use "Make it UST" once to create it';
    document.getElementById('pub').textContent = '—';
    return;
  }
  const s = await W.signerFromKeys(stored.privateKey, stored.publicKey);
  document.getElementById('id').textContent = s.key_id;
  document.getElementById('pub').textContent = s.pub;
})();
(async () => {
  try {
    const { pendingVerify } = await chrome.storage.session.get('pendingVerify');
    if (pendingVerify) {
      await chrome.storage.session.remove('pendingVerify');
      chrome.action.setBadgeText({ text: '' });
      inEl.value = pendingVerify;
      run();
    }
  } catch { /* opened outside the extension — paste still works */ }
})();
