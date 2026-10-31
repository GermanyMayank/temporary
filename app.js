'use strict';
/*
 * Temporary: a password-protected chat room on mayankvekariya.de/temporary
 * Everything is stored ENCRYPTED in the public repo GermanyMayank/temporary-data.
 *   room.json          -> salt + the write key for temporary-data, encrypted with the room password
 *   messages/<id>.json -> one encrypted message each
 *   blobs/<id>.bin     -> encrypted file contents
 * The password never leaves the browser. Encryption: PBKDF2-SHA256 -> AES-256-GCM.
 */
const VERSION = '1.0.0';
const OWNER = 'GermanyMayank';
const REPO = 'temporary-data';
const BRANCH = 'main';
const ITER = 310000;
const MAX_FILE = 25 * 1024 * 1024;
const POLL_VISIBLE = 3000;
const POLL_HIDDEN = 20000;

const local = ['localhost', '127.0.0.1'].includes(location.hostname);
const API = (local && new URLSearchParams(location.search).get('api')) || 'https://api.github.com';
const R = `${API}/repos/${OWNER}/${REPO}`;

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

const state = {
  key: null,        // AES key from password
  token: null,      // decrypted write key
  roomSha: null,    // blob sha of room.json when unlocked
  salt: null,
  etag: null,
  seen: new Map(),  // path -> sha
  tree: new Map(),  // path -> sha (current)
  timer: null,
  busy: false,
  me: null,
};

/* ---------- small helpers ---------- */
function b64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(str) {
  const bin = atob(str.replace(/\s/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function rid() {
  const r = crypto.getRandomValues(new Uint8Array(6));
  return Date.now().toString(36).padStart(9, '0') + '-' + Array.from(r, (b) => b.toString(16).padStart(2, '0')).join('');
}
function size(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(0) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}
function when(ts) {
  const d = new Date(ts);
  const same = d.toDateString() === new Date().toDateString();
  return (same ? '' : d.toLocaleDateString([], { day: 'numeric', month: 'short' }) + ', ') +
    d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
function deviceId() {
  try {
    let id = localStorage.getItem('tmp.device');
    if (!id) { id = rid(); localStorage.setItem('tmp.device', id); }
    return id;
  } catch { return 'anon'; }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------- crypto ---------- */
async function deriveKey(password, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITER },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return out;
}
async function unseal(key, bytes) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12) }, key, bytes.subarray(12)));
}

/* ---------- GitHub ---------- */
class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

async function gh(path, opts = {}, token = state.token) {
  const headers = { Accept: 'application/vnd.github+json', ...(opts.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (opts.body) headers['Content-Type'] = 'application/json';
  let res;
  try {
    res = await fetch(path.startsWith('http') ? path : R + path, {
      method: opts.method || 'GET', headers, cache: 'no-store',
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
  } catch {
    throw new ApiError(0, 'You seem to be offline. Messages will appear when the connection is back.');
  }
  if (res.status === 304) return { notModified: true };
  if (!res.ok) {
    let m = '';
    try { m = (await res.json()).message || ''; } catch { /* ignore */ }
    if (res.status === 401) throw new ApiError(401, 'The room key stopped working. The owner needs to set the room up again.');
    if (res.status === 403 && /rate limit/i.test(m)) throw new ApiError(403, 'GitHub is busy for a moment. Try again in a minute.');
    throw new ApiError(res.status, m || `GitHub error ${res.status}`);
  }
  const data = res.status === 204 ? {} : await res.json();
  data.__etag = res.headers.get('ETag');
  return data;
}

async function readRoom(token = null) {
  try {
    const d = await gh(`/contents/room.json?ref=${BRANCH}&t=${Date.now()}`, {}, token);
    return { room: JSON.parse(dec.decode(unb64(d.content))), sha: d.sha };
  } catch (e) {
    if (e.status === 404 || e.status === 409) return null;
    throw e;
  }
}

async function putFile(path, bytes, message) {
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await gh(`/contents/${path}`, { method: 'PUT', body: { message, content: b64(bytes), branch: BRANCH } });
    } catch (e) {
      if ((e.status === 409 || e.status === 422 || e.status === 500 || e.status === 502) && attempt < 4) {
        await sleep(400 + Math.random() * 900 * (attempt + 1));
        continue;
      }
      throw e;
    }
  }
}

// Replace the whole branch with a single commit holding just room.json (removes all history).
async function resetBranch(roomBytes, token) {
  let hasBranch = true;
  try { await gh(`/git/ref/heads/${BRANCH}`, {}, token); } catch (e) {
    if (e.status === 404 || e.status === 409) hasBranch = false; else throw e;
  }
  if (!hasBranch) {
    await gh('/contents/room.json', { method: 'PUT', body: { message: 'Set up room', content: b64(roomBytes), branch: BRANCH } }, token);
    return;
  }
  const blob = await gh('/git/blobs', { method: 'POST', body: { content: b64(roomBytes), encoding: 'base64' } }, token);
  const tree = await gh('/git/trees', { method: 'POST', body: { tree: [{ path: 'room.json', mode: '100644', type: 'blob', sha: blob.sha }] } }, token);
  const commit = await gh('/git/commits', { method: 'POST', body: { message: 'Fresh room', tree: tree.sha, parents: [] } }, token);
  await gh(`/git/refs/heads/${BRANCH}`, { method: 'PATCH', body: { sha: commit.sha, force: true } }, token);
}

/* ---------- views ---------- */
function show(view) {
  for (const v of ['lockView', 'setupView', 'chatView']) $(v).hidden = v !== view;
  $('composer').hidden = view !== 'chatView';
  $('chatActions').hidden = view !== 'chatView';
}
function banner(text) {
  $('banner').textContent = text || '';
  $('banner').hidden = !text;
}

/* ---------- unlock ---------- */
async function unlock() {
  const pw = $('pw').value;
  const name = $('myName').value.trim();
  if (!pw) { $('lockMsg').textContent = 'Type the password first.'; return; }
  $('unlockBtn').disabled = true;
  $('lockMsg').textContent = 'Opening…';
  try {
    const r = await readRoom();
    if (!r) { $('lockMsg').textContent = 'This room is not set up yet.'; return; }
    const salt = unb64(r.room.salt);
    const key = await deriveKey(pw, salt);
    let token;
    try { token = dec.decode(await unseal(key, unb64(r.room.token))); } catch {
      $('lockMsg').textContent = 'Wrong password.';
      return;
    }
    state.key = key; state.token = token; state.roomSha = r.sha; state.salt = r.room.salt;
    state.me = name || 'Someone';
    try { localStorage.setItem('tmp.name', name); } catch { /* ignore */ }
    $('pw').value = '';
    $('lockMsg').textContent = '';
    enterChat();
  } catch (e) {
    $('lockMsg').textContent = e.message;
  } finally {
    $('unlockBtn').disabled = false;
  }
}

function lock(msg) {
  clearTimeout(state.timer);
  state.key = null; state.token = null; state.etag = null;
  state.seen.clear(); state.tree.clear();
  for (const u of urls) URL.revokeObjectURL(u);
  urls.clear();
  $('list').replaceChildren();
  $('empty').hidden = false;
  banner('');
  show('lockView');
  $('lockMsg').textContent = msg || '';
  $('pw').focus();
}

/* ---------- owner setup ---------- */
async function setup() {
  const token = $('setToken').value.trim();
  const pw = $('setPw').value;
  const msg = $('setupMsg');
  if (!token) { msg.textContent = 'Paste the GitHub key first.'; return; }
  if (pw.length < 12) { msg.textContent = 'Use at least 12 characters, for example three words.'; return; }
  if (pw !== $('setPw2').value) { msg.textContent = 'The two passwords are different.'; return; }
  $('setupBtn').disabled = true;
  msg.textContent = 'Checking the key…';
  try {
    const repo = await gh('', {}, token);
    if (!repo.permissions || !repo.permissions.push) { msg.textContent = 'This key cannot write to temporary-data.'; return; }
    msg.textContent = 'Locking the room…';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(pw, salt);
    const room = { v: 1, salt: b64(salt), token: b64(await seal(key, enc.encode(token))) };
    await resetBranch(enc.encode(JSON.stringify(room)), token);
    $('setToken').value = ''; $('setPw').value = ''; $('setPw2').value = '';
    const r = await readRoom(token);
    state.key = key; state.token = token; state.roomSha = r ? r.sha : null; state.salt = room.salt;
    const typed = $('myName').value.trim();
    state.me = typed || 'Owner';
    try { if (typed) localStorage.setItem('tmp.name', typed); } catch { /* ignore */ }
    msg.textContent = '';
    enterChat();
  } catch (e) {
    msg.textContent = e.status === 401 ? 'GitHub did not accept this key.' : e.message;
  } finally {
    $('setupBtn').disabled = false;
  }
}

/* ---------- chat ---------- */
function enterChat() {
  show('chatView');
  $('text').focus();
  poll(true);
}

function schedule() {
  clearTimeout(state.timer);
  if (!state.token) return;
  state.timer = setTimeout(() => poll(), document.hidden ? POLL_HIDDEN : POLL_VISIBLE);
}

async function poll(force = false) {
  if (!state.token || state.busy) { schedule(); return; }
  state.busy = true;
  try {
    const ref = await gh(`/git/ref/heads/${BRANCH}`, { headers: !force && state.etag ? { 'If-None-Match': state.etag } : {} });
    if (ref.notModified) return;
    state.etag = ref.__etag;
    const t = await gh(`/git/trees/${ref.object.sha}?recursive=1`);
    const now = new Map();
    for (const e of t.tree) if (e.type === 'blob') now.set(e.path, e.sha);
    // Room replaced (new password or cleared)?
    const roomSha = now.get('room.json');
    if (roomSha && roomSha !== state.roomSha) {
      const r = await readRoom();
      if (r && r.room.salt !== state.salt) { lock('The room password was changed. Enter the new one.'); return; }
      state.roomSha = roomSha;
    }
    // Messages removed (room cleared)?
    for (const p of [...state.seen.keys()]) {
      if (!now.has(p)) {
        state.seen.delete(p);
        const li = document.querySelector(`[data-path="${CSS.escape(p)}"]`);
        if (li) li.remove();
      }
    }
    state.tree = now;
    const fresh = [...now.keys()].filter((p) => p.startsWith('messages/') && p.endsWith('.json') && !state.seen.has(p)).sort();
    for (const p of fresh) {
      try {
        const blob = await gh(`/git/blobs/${now.get(p)}`);
        const m = JSON.parse(dec.decode(await unseal(state.key, unb64(blob.content))));
        render(p, m);
      } catch { /* unreadable message (old password): skip */ }
      state.seen.set(p, now.get(p));
    }
    $('empty').hidden = state.seen.size > 0;
    banner('');
  } catch (e) {
    if (e.status === 401) { lock(e.message); return; }
    banner(e.message);
  } finally {
    state.busy = false;
    schedule();
  }
}

const urls = new Set();
function linkify(el, text) {
  const re = /\bhttps?:\/\/[^\s<>"']+/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    let url = m[0].replace(/[.,!?;:)\]]+$/, '');
    if (m.index > last) el.append(text.slice(last, m.index));
    const a = document.createElement('a');
    a.href = url; a.textContent = url; a.target = '_blank'; a.rel = 'noopener noreferrer';
    el.append(a);
    last = m.index + url.length;
  }
  if (last < text.length) el.append(text.slice(last));
}

function chip(label, fn) {
  const b = document.createElement('button');
  b.type = 'button'; b.className = 'chip'; b.textContent = label;
  b.addEventListener('click', () => fn(b));
  return b;
}
function flash(b, text) {
  const old = b.textContent;
  b.textContent = text; b.classList.add('done');
  setTimeout(() => { b.textContent = old; b.classList.remove('done'); }, 1400);
}

function render(path, m) {
  const li = document.createElement('li');
  li.className = 'item' + (m.dev === deviceId() ? ' mine' : '');
  li.dataset.path = path;
  li.dataset.ts = m.ts;
  const meta = document.createElement('span');
  meta.className = 'meta';
  meta.textContent = `${m.from || 'Someone'}, ${when(m.ts)}`;
  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  const tools = document.createElement('div');
  tools.className = 'tools';

  if (m.type === 'file') {
    bubble.classList.add('file');
    const n = document.createElement('span'); n.className = 'fname'; n.textContent = m.name;
    const s = document.createElement('span'); s.className = 'fsize'; s.textContent = size(m.size);
    bubble.append(n, s);
    tools.append(chip('Download', (b) => download(m, b)));
    if (/^image\/(png|jpeg|gif|webp)$/.test(m.mime) && m.size < 8 * 1048576) preview(m, bubble);
  } else {
    linkify(bubble, m.text);
    tools.append(chip('Copy', async (b) => {
      try { await navigator.clipboard.writeText(m.text); flash(b, 'Copied'); }
      catch { selectText(bubble); flash(b, 'Selected'); }
    }));
  }
  li.append(meta, bubble, tools);

  // keep order by timestamp
  const list = $('list');
  const after = [...list.children].find((c) => Number(c.dataset.ts) > m.ts);
  const nearBottom = window.innerHeight + window.scrollY >= document.body.scrollHeight - 120;
  list.insertBefore(li, after || null);
  if (nearBottom || m.dev === deviceId()) li.scrollIntoView({ block: 'end' });
}

function selectText(el) {
  const r = document.createRange(); r.selectNodeContents(el);
  const s = getSelection(); s.removeAllRanges(); s.addRange(r);
}

async function fileBytes(m) {
  const sha = state.tree.get(m.blob);
  if (!sha) throw new Error('This file is no longer in the room.');
  const blob = await gh(`/git/blobs/${sha}`);
  return unseal(state.key, unb64(blob.content));
}
async function download(m, b) {
  b.textContent = 'Loading…';
  try {
    const bytes = await fileBytes(m);
    const url = URL.createObjectURL(new Blob([bytes], { type: m.mime || 'application/octet-stream' }));
    urls.add(url);
    const a = document.createElement('a');
    a.href = url; a.download = m.name || 'file';
    document.body.append(a); a.click(); a.remove();
    b.textContent = 'Download';
    flash(b, 'Saved');
  } catch (e) {
    b.textContent = 'Download';
    banner(e.message);
  }
}
async function preview(m, bubble) {
  try {
    const bytes = await fileBytes(m);
    const url = URL.createObjectURL(new Blob([bytes], { type: m.mime }));
    urls.add(url);
    const img = document.createElement('img');
    img.alt = m.name; img.src = url;
    bubble.prepend(img);
  } catch { /* preview is optional */ }
}

/* ---------- sending ---------- */
async function sendMessage(m) {
  const id = rid();
  m.ts = Date.now(); m.from = state.me; m.dev = deviceId();
  const body = await seal(state.key, enc.encode(JSON.stringify(m)));
  await putFile(`messages/${id}.json`, body, 'msg');
}

async function sendText() {
  const text = $('text').value;
  if (!text.trim() || !state.token) return;
  $('sendBtn').disabled = true;
  try {
    await sendMessage({ type: 'text', text });
    $('text').value = '';
    autosize();
    poll(true);
  } catch (e) { banner(e.message); }
  finally { $('sendBtn').disabled = false; $('text').focus(); }
}

async function sendFiles(files) {
  if (!state.token) return;
  for (const f of files) {
    if (f.size > MAX_FILE) { banner(`${f.name} is larger than 25 MB.`); continue; }
    banner(`Sending ${f.name}…`);
    try {
      const id = rid();
      const bytes = new Uint8Array(await f.arrayBuffer());
      await putFile(`blobs/${id}.bin`, await seal(state.key, bytes), 'file');
      await sendMessage({ type: 'file', name: f.name || 'pasted-file', size: f.size, mime: f.type, blob: `blobs/${id}.bin` });
      banner('');
    } catch (e) { banner(e.message); return; }
  }
  poll(true);
}

async function clearRoom() {
  if (!confirm('Delete every message and file in this room for everyone?')) return;
  try {
    const r = await readRoom(state.token);
    await resetBranch(enc.encode(JSON.stringify(r.room)), state.token);
    state.etag = null;
    poll(true);
  } catch (e) { banner(e.message); }
}

function autosize() {
  const t = $('text');
  t.style.height = 'auto';
  t.style.height = Math.min(t.scrollHeight, 160) + 'px';
}

/* ---------- wiring ---------- */
function init() {
  try { $('myName').value = localStorage.getItem('tmp.name') || ''; } catch { /* ignore */ }
  $('unlockBtn').addEventListener('click', unlock);
  $('pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
  $('myName').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
  $('toSetup').addEventListener('click', () => { show('setupView'); $('setToken').focus(); });
  $('toLock').addEventListener('click', () => show('lockView'));
  $('setupBtn').addEventListener('click', setup);
  $('lockBtn').addEventListener('click', () => lock());
  $('clearBtn').addEventListener('click', clearRoom);
  $('sendBtn').addEventListener('click', sendText);
  $('attachBtn').addEventListener('click', () => $('fileIn').click());
  $('fileIn').addEventListener('change', (e) => { sendFiles([...e.target.files]); e.target.value = ''; });
  $('text').addEventListener('input', autosize);
  $('text').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !matchMedia('(pointer: coarse)').matches) { e.preventDefault(); sendText(); }
  });
  $('text').addEventListener('paste', (e) => {
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) { e.preventDefault(); sendFiles(files); }
  });
  let depth = 0;
  addEventListener('dragenter', (e) => { if (state.token && e.dataTransfer?.types.includes('Files')) { depth++; $('drop').hidden = false; } });
  addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; $('drop').hidden = true; } });
  addEventListener('dragover', (e) => e.preventDefault());
  addEventListener('drop', (e) => {
    e.preventDefault(); depth = 0; $('drop').hidden = true;
    if (state.token && e.dataTransfer?.files.length) sendFiles([...e.dataTransfer.files]);
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden && state.token) poll(); });
  addEventListener('online', () => state.token && poll(true));
  show('lockView');
  $('pw').focus();
}
init();
