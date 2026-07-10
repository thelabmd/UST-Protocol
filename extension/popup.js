// SPDX-License-Identifier: Apache-2.0
import * as W from './lib/ust-web-signer.mjs';
import { verify } from './lib/ust-verify.mjs';

function openDB() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('ust-signer', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('keys');
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function idbGet(key) {
  const db = await openDB();
  return new Promise((res) => { const t = db.transaction('keys').objectStore('keys').get(key); t.onsuccess = () => res(t.result ?? null); t.onerror = () => res(null); });
}

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

// ── Verify mode: the extension is the RECIPIENT'S trusted verifier. It regenerates everything it shows from the
// SIGNED bytes — the sender's preamble (Source:, header) is never displayed as truth. Runs locally; nothing leaves
// the browser. Same extraction as the web verifier: full blob / bare base64 / raw JSON. ──
const vin = document.getElementById('vin'), vout = document.getElementById('vout');
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function b64decodeUtf8(b64) {
  const bin = atob(b64.replace(/\s+/g, ''));
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}
function extractDoc(input) {
  let s = input.trim();
  const marker = '———UST(base64)———';
  if (s.includes(marker)) s = s.slice(s.lastIndexOf(marker) + marker.length).trim();
  if (s.startsWith('{')) return JSON.parse(s);
  return JSON.parse(b64decodeUtf8(s));
}
// ── DISPLAY-ONLY markdown (ported from the web verifier): escape-first, links http(s)-only, images never
// fetched, no raw-HTML passthrough. MD is the default view; RAW is the exact signed string, one click away. ──
const partVals = [];
function mdSafe(src) {
  let t = esc(src);
  t = t.replace(/```([\s\S]*?)```/g, (m, code) => '<pre>' + code.replace(/^\n|\n$/g, '') + '</pre>');
  t = t.replace(/^######\s?(.+)$/gm, '<h3>$1</h3>').replace(/^#####\s?(.+)$/gm, '<h3>$1</h3>')
       .replace(/^####\s?(.+)$/gm, '<h3>$1</h3>').replace(/^###\s?(.+)$/gm, '<h3>$1</h3>')
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
function objectMd(v) {
  return Object.entries(v).map(([k, val]) => {
    if (typeof val === 'string') {
      const rich = val.length > 80 || /[\n#*`]/.test(val);
      const looksId = /^(sha256:|ust:|https?:)/.test(val) && !/\s/.test(val);
      const body = looksId ? '<span class="fv mono">' + esc(val) + '</span>'
        : rich ? '<div class="fv md">' + mdSafe(val) + '</div>' : '<span class="fv">' + esc(val) + '</span>';
      return '<div class="fld"><span class="fk">' + esc(k) + '</span>' + body + '</div>';
    }
    return '<div class="fld"><span class="fk">' + esc(k) + '</span><pre style="margin:0">' + esc(JSON.stringify(val, null, 2)) + '</pre></div>';
  }).join('');
}
const rawOf = (e) => e.kind === 'text' ? e.v : JSON.stringify(e.v, null, 2);
const mdOf = (e) => e.kind === 'text' ? mdSafe(e.v) : objectMd(e.v);
function renderContent(data) {
  partVals.length = 0;
  return Object.entries(data || {}).map(([name, part]) => {
    if (part && part.value !== undefined) {
      const v = part.value;
      const isText = v && typeof v === 'object' && typeof v.text === 'string';
      const isObj = !isText && v && typeof v === 'object' && !Array.isArray(v);
      const entry = isText ? { kind: 'text', v: v.text } : { kind: isObj ? 'obj' : 'text', v: isObj ? v : JSON.stringify(v, null, 2) };
      const i = partVals.push(entry) - 1;
      const toggle = (isText || isObj)
        ? '<span class="viewtoggle" data-ci="' + i + '"><button class="vt on" data-mode="md">md</button><button class="vt" data-mode="raw">raw</button></span>'
        : '';
      return '<div class="pblock"><div class="phead"><span class="plabel">' + esc(name) + (part.kind ? ' · ' + esc(part.kind) : '') + '</span>' + toggle + '</div><div class="content mdview md" data-ci="' + i + '">' + mdOf(entry) + '</div></div>';
    }
    return '<div class="pblock"><div class="phead"><span class="plabel">' + esc(name) + ' · ' + esc(part && part.privacy || 'private') + '</span></div><div class="content">' + esc(part && part.commit || '(private — committed, not revealed)') + '</div></div>';
  }).join('');
}
vout.addEventListener('click', (e) => {
  const btn = e.target.closest('.vt');
  if (!btn) return;
  const wrap = btn.closest('.viewtoggle');
  const ci = wrap.dataset.ci;
  const box = vout.querySelector('.content[data-ci="' + ci + '"]');
  if (!box) return;
  wrap.querySelectorAll('.vt').forEach((b) => b.classList.toggle('on', b === btn));
  if (btn.dataset.mode === 'md') { box.classList.add('mdview', 'md'); box.innerHTML = mdOf(partVals[ci]); }
  else { box.classList.remove('mdview', 'md'); box.innerHTML = esc(rawOf(partVals[ci])); }
});

async function runVerify() {
  const raw = vin.value.trim();
  vout.innerHTML = '';
  if (!raw) return;

  let doc;
  try { doc = extractDoc(raw); }
  catch { vout.innerHTML = '<div class="verdict bad">UNREADABLE</div><div class="err">Not a UST blob, base64, or JSON.</div>'; return; }

  try {
    const r = await verify(doc, { context: 'data' });
    const valid = typeof r.result === 'string' && r.result.slice(0, 6) === 'VALID:';
    const st = doc.state || {}, id = st.id || {};
    if (valid) {
      vout.innerHTML = '<div class="verdict ok">' + esc(r.result) + '</div>' +
        renderContent(st.data) +
        '<div class="kv"><span>key</span> ' + esc(id.key_id || '') + '<br><span>time</span> ' + esc(st.time && st.time.generated_at || '') + ' · <span>frame</span> ' + esc(id.ust_id || '') + '</div>' +
        '<p class="note">Proven: the exact bytes above · the signing key · the claimed time. <b>Not</b> proven: who published it, or where it came from — a <i>Source:</i> line in the pasted text is the sender\'s unverified claim.</p>';
    } else {
      vout.innerHTML = '<div class="verdict bad">' + esc(r.result || 'INVALID') + '</div>' +
        '<div class="err">' + esc(r.error || '') + (r.detail ? ' — ' + esc(r.detail) : '') + '</div>' +
        '<p class="note">The bytes, hashes, or signature are inconsistent — a genuine UST edited in transit fails exactly here.</p>';
    }
  } catch (e) {
    vout.innerHTML = '<div class="verdict bad">ERROR</div><div class="err">' + esc(e.message || String(e)) + '</div>';
  }
}
vin.addEventListener('input', runVerify);

// ── "Verify UST" context menu handoff: the selection arrives via storage.session — fill the box and verify. ──
(async () => {
  try {
    const { pendingVerify } = await chrome.storage.session.get('pendingVerify');
    if (pendingVerify) {
      await chrome.storage.session.remove('pendingVerify');
      chrome.action.setBadgeText({ text: '' });            // clear the fallback badge, if any
      vin.value = pendingVerify;
      runVerify();
    }
  } catch { /* storage unavailable (e.g. opened as a plain page) — paste still works */ }
})();
