// SPDX-License-Identifier: Apache-2.0
import * as W from './lib/ust-web-signer.mjs';

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
