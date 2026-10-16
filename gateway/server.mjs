// Secure Secrets Exchange - Qatom gateway
// Sits in front of the open-source secrets core (MIT, (c) 2012-ongoing delano, contributors).
// Paid tools (create, request) answer only Qatom's fulfilment call; retrieve and sending are free
// and need no Qatom account. Inbound payloads are stored encrypted, returned once, then deleted.
import http from 'node:http';
import crypto from 'node:crypto';

const env = process.env;
const PORT = Number(env.PORT || 8080);
const PUBLIC_ORIGIN = (env.PUBLIC_ORIGIN || 'http://localhost:8080').replace(/\/$/, '');
const CORE_URL = (env.CORE_URL || 'http://app:3000').replace(/\/$/, '');
const CORE_USER = env.CORE_API_USER || '';
const CORE_TOKEN = env.CORE_API_TOKEN || '';
const SERVICE_PATH = env.SERVICE_PATH || '';
const FULFIL = env.QATOM_FULFILMENT_TOKEN || '';
const INBOX_TOKEN = env.INBOX_TOKEN || '';
const ENC_KEY = crypto.createHash('sha256').update(env.GATEWAY_KEY || '').digest();
const PRICE = { create: '0.100', request: '0.100', retrieve: '0.000' };
const ITEM_IDS = { create: env.ITEM_ID_CREATE || '', request: env.ITEM_ID_REQUEST || '', retrieve: env.ITEM_ID_RETRIEVE || '', feedback: env.ITEM_ID_FEEDBACK || '' };
const MAX_PAYLOAD = 10000;
const TTL_MIN = 1, TTL_MAX = 168, TTL_DEFAULT = 168;
const NAME = 'Secure Secrets Exchange';
const CORE_VERSION = env.CORE_VERSION || 'v0.26.14';
const SOURCE_URL = env.SOURCE_URL || 'https://github.com/StarwaterHeaven/secure-secrets-exchange';
const CORE_SOURCE_URL = 'https://github.com/onetimesecret/onetimesecret';
const SECURITY_CONTACT = env.SECURITY_CONTACT || 'mailto:support@todaq.net';
const E2E_PREFIX = 'sse-e2e-v1.';
const E2E_MAX = 14000; // ciphertext of a 10000-character secret, base64url, plus prefix
const isE2E = (s) => typeof s === 'string' && s.startsWith(E2E_PREFIX);
function e2eValid(s) {
  if (!/^sse-e2e-v1\.[A-Za-z0-9_-]+$/.test(s) || s.length > E2E_MAX) return false;
  return Buffer.from(s.slice(E2E_PREFIX.length), 'base64url').length >= 12 + 16 + 1;
}

if (!env.GATEWAY_KEY || env.GATEWAY_KEY.length < 32) { console.error('GATEWAY_KEY missing or too short'); process.exit(1); }

// ---------- storage: Valkey/Redis when REDIS_URL is set, memory otherwise (tests) ----------
let store;
if (env.REDIS_URL) {
  const { createClient } = await import('redis');
  const c = createClient({ url: env.REDIS_URL });
  c.on('error', (e) => console.error('valkey', e.message));
  await c.connect();
  store = {
    get: (k) => c.get(k),
    set: (k, v, ttl) => c.set(k, v, { EX: ttl }),
    setnx: async (k, v, ttl) => (await c.set(k, v, { EX: ttl, NX: true })) === 'OK',
    del: (k) => c.del(k),
    getdel: (k) => c.getDel(k),
    ttl: (k) => c.ttl(k),
    incr: async (k, ttl) => { const n = await c.incr(k); if (n === 1) await c.expire(k, ttl); return n; },
    lpush: async (k, v, cap) => { await c.lPush(k, v); await c.lTrim(k, 0, cap - 1); },
    lrange: (k, n) => c.lRange(k, 0, n - 1),
  };
} else {
  const m = new Map();
  const live = (k) => { const e = m.get(k); if (!e) return null; if (e.x && e.x < Date.now()) { m.delete(k); return null; } return e; };
  store = {
    get: async (k) => live(k)?.v ?? null,
    set: async (k, v, ttl) => { m.set(k, { v, x: Date.now() + ttl * 1000 }); },
    setnx: async (k, v, ttl) => { if (live(k)) return false; m.set(k, { v, x: Date.now() + ttl * 1000 }); return true; },
    del: async (k) => { m.delete(k); },
    getdel: async (k) => { const e = live(k); m.delete(k); return e?.v ?? null; },
    ttl: async (k) => { const e = live(k); return e ? Math.round((e.x - Date.now()) / 1000) : -2; },
    incr: async (k, ttl) => { const e = live(k); const n = (e ? Number(e.v) : 0) + 1; m.set(k, { v: String(n), x: e?.x || Date.now() + ttl * 1000 }); return n; },
    lpush: async (k, v, cap) => { const e = live(k); const a = e ? JSON.parse(e.v) : []; a.unshift(v); m.set(k, { v: JSON.stringify(a.slice(0, cap)), x: 0 }); },
    lrange: async (k, n) => { const e = live(k); return e ? JSON.parse(e.v).slice(0, n) : []; },
  };
}

// ---------- browser scripts (published; their SHA-256 is pinned in each page's CSP and listed on /security) ----------
const VIEWER_JS = String.raw`(function () {
  var P = 'sse-e2e-v1.';
  function ub(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; var b = atob(s), a = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
  var key = location.hash.slice(1), id = location.pathname.split('/').pop();
  var st = document.getElementById('st'), go = document.getElementById('go'), out = document.getElementById('out');
  if (!/^[A-Za-z0-9_-]{43}$/.test(key)) { st.textContent = 'This link is missing its key (the part after #). Nothing was opened. Ask the sender for the complete link.'; go.disabled = true; return; }
  go.onclick = async function () {
    go.disabled = true; st.textContent = 'Opening...';
    try {
      var r = await fetch('/api/e2e/reveal/' + id, { method: 'POST' }), j = await r.json();
      if (!r.ok || !j.ok) { st.textContent = (j.error && j.error.message) || 'This secret is no longer available.'; return; }
      var ct = j.result.ciphertext; if (ct.indexOf(P) !== 0) throw new Error('format');
      var raw = ub(ct.slice(P.length));
      var k = await crypto.subtle.importKey('raw', ub(key), 'AES-GCM', false, ['decrypt']);
      var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, k, raw.slice(12));
      out.value = new TextDecoder().decode(pt); out.hidden = false; go.hidden = true;
      history.replaceState(null, '', location.pathname);
      st.textContent = 'Decrypted in your browser. The server only ever held the encrypted copy, and it has now been deleted. Copy the secret now.';
    } catch (e) { st.textContent = 'Could not decrypt. The link may be incomplete or altered. The encrypted copy was deleted when it was opened.'; }
  };
})();`;
const SENDER_JS = String.raw`(function () {
  var P = 'sse-e2e-v1.', key = location.hash.slice(1);
  if (!/^[A-Za-z0-9_-]{43}$/.test(key)) return;
  function ub(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; var b = atob(s), a = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
  function bu(a) { var s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  var f = document.getElementById('f'), badge = document.getElementById('e2e'), done = false;
  badge.hidden = false;
  f.addEventListener('submit', async function (ev) {
    if (done) return; ev.preventDefault();
    var k = await crypto.subtle.importKey('raw', ub(key), 'AES-GCM', false, ['encrypt']);
    async function enc(t) { var iv = crypto.getRandomValues(new Uint8Array(12)); var c = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, k, new TextEncoder().encode(t))); var o = new Uint8Array(12 + c.length); o.set(iv); o.set(c, 12); return P + bu(o); }
    var s = document.getElementById('s'), n = document.getElementById('n');
    s.removeAttribute('maxlength'); n.removeAttribute('maxlength');
    s.value = await enc(s.value); if (n.value) n.value = await enc(n.value);
    done = true; f.submit();
  });
})();`;
const cspHash = (js) => `'sha256-${crypto.createHash('sha256').update(js, 'utf8').digest('base64')}'`;
const hexHash = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// ---------- helpers ----------
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const rand = (n) => crypto.randomBytes(n).toString('base64url');
function same(a, b) { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); }
function seal(text) { const iv = crypto.randomBytes(12); const c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv); const ct = Buffer.concat([c.update(text, 'utf8'), c.final()]); return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64'); }
function open(b64) { const b = Buffer.from(b64, 'base64'); const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'); }
const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
const isoIn = (sec) => new Date(Date.now() + sec * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function send(res, code, body, type = 'application/json; charset=utf-8', extra = {}) {
  const data = type.startsWith('application/json') ? JSON.stringify(body, null, 2) : body;
  res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', ...extra });
  res.end(data);
}
const notFound = (res) => send(res, 404, { ok: false, error: { code: 'not_found', message: 'Nothing here.', next_step: `See ${PUBLIC_ORIGIN}/llms.txt` } });
function err(res, code, item, ecode, message, next_step, extra = {}) {
  send(res, code, { ok: false, item, error: { code: ecode, message, next_step }, ...extra });
}

async function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(Object.assign(new Error('too large'), { tooLarge: true })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
async function inputs(req, url) {
  const q = Object.fromEntries(url.searchParams.entries());
  if (req.method === 'GET') return q;
  const raw = await readBody(req);
  if (!raw.trim()) return q;
  const ct = req.headers['content-type'] || '';
  if (ct.includes('application/x-www-form-urlencoded')) return { ...q, ...Object.fromEntries(new URLSearchParams(raw)) };
  try { const j = JSON.parse(raw); if (j && typeof j === 'object' && !Array.isArray(j)) return { ...q, ...j }; } catch {}
  throw Object.assign(new Error('bad json'), { badJson: true });
}
function onlyKeys(obj, allowed) { return Object.keys(obj).filter((k) => !allowed.includes(k)); }
function ttlFrom(v) {
  if (v === undefined || v === null || v === '') return { value: TTL_DEFAULT, defaulted: true };
  const n = Number(v);
  if (!Number.isInteger(n) || n < TTL_MIN || n > TTL_MAX) return { bad: true };
  return { value: n, defaulted: false };
}
async function limited(key, max, windowSec) { return (await store.incr(`sse:rl:${key}`, windowSec)) > max; }
const clientIp = (req) => (req.headers['cf-connecting-ip'] || req.socket.remoteAddress || 'unknown').toString();
// Talk to the core as if through the public hostname, so its host checks and links line up.
function corePost(path, obj) {
  const u = new URL(CORE_URL + path), data = JSON.stringify(obj);
  return new Promise((resolve, reject) => {
    const rq = http.request({ hostname: u.hostname, port: u.port || 80, path: u.pathname, method: 'POST', timeout: 15000,
      headers: { 'content-type': 'application/json', accept: 'application/json', 'content-length': Buffer.byteLength(data),
        host: new URL(PUBLIC_ORIGIN).host, 'x-forwarded-proto': new URL(PUBLIC_ORIGIN).protocol.replace(':', ''),
        authorization: 'Basic ' + Buffer.from(`${CORE_USER}:${CORE_TOKEN}`).toString('base64') } }, (rs) => {
      let b = ''; rs.setEncoding('utf8'); rs.on('data', (c) => (b += c)); rs.on('end', () => resolve({ ok: rs.statusCode >= 200 && rs.statusCode < 300, status: rs.statusCode, body: b }));
    });
    rq.on('timeout', () => rq.destroy(new Error('core timeout'))); rq.on('error', reject); rq.end(data);
  });
}
function paidOk(req) { return FULFIL && same(req.headers['authorization'] || '', `Bearer ${FULFIL}`); }

// ---------- tools ----------
async function toolCreate(req, res, url) {
  const item = 'create';
  const p = await inputs(req, url);
  const extra = onlyKeys(p, ['payload', 'ttl_hours', 'passphrase']);
  if (extra.length) return err(res, 400, item, 'unknown_parameter', `Unknown input: ${extra.join(', ')}.`, 'Send only payload, ttl_hours and passphrase.', { accepts: ['payload', 'ttl_hours', 'passphrase'] });
  const payload = typeof p.payload === 'string' ? p.payload : '';
  if (!payload.trim()) return err(res, 400, item, 'payload_required', 'payload is required: the secret text to share.', 'Call again with payload.');
  if (isE2E(payload)) return createE2E(res, p, payload);
  if (payload.length > MAX_PAYLOAD) return err(res, 413, item, 'payload_too_large', `payload is ${payload.length} characters; the limit is ${MAX_PAYLOAD}.`, 'Send a shorter secret, or split it.');
  const ttl = ttlFrom(p.ttl_hours);
  if (ttl.bad) return err(res, 400, item, 'bad_value', `ttl_hours must be a whole number from ${TTL_MIN} to ${TTL_MAX}.`, `Use ${TTL_MIN}-${TTL_MAX}, or leave it out for ${TTL_DEFAULT}.`, { accepts: [{ input: 'ttl_hours', unit: 'hours', range: [TTL_MIN, TTL_MAX] }] });
  const pass = typeof p.passphrase === 'string' && p.passphrase.length ? p.passphrase : null;
  if (pass && pass.length > 128) return err(res, 400, item, 'bad_value', 'passphrase is limited to 128 characters.', 'Use a shorter passphrase.');
  const body = { secret: { kind: 'conceal', secret: payload, ttl: ttl.value * 3600, ...(pass ? { passphrase: pass } : {}) } };
  let r, j;
  try {
    r = await corePost('/api/v2/secret/conceal', body);
    j = JSON.parse(r.body);
  } catch (e) { console.error('core', e.message); return err(res, 502, item, 'internal_error', 'The secret store did not answer.', 'Try again in a minute.'); }
  const sec = j?.record?.secret, rec = j?.record?.receipt;
  if (!r.ok || !sec?.identifier) { console.error('core said', r.status, String(r.body).slice(0, 300)); return err(res, 502, item, 'internal_error', 'The secret store refused the secret.', 'Check the inputs and try again.'); }
  const expires = isoIn(ttl.value * 3600);
  send(res, 200, {
    ok: true, item: 'secure-secret-create', answer_type: 'action', as_of: nowIso(),
    inputs: { payload: `[${payload.length} characters, not echoed]`, ...(p.ttl_hours !== undefined ? { ttl_hours: ttl.value } : {}), ...(pass ? { passphrase: '[set, not echoed]' } : {}) },
    defaulted_inputs: ttl.defaulted ? { ttl_hours: { value: TTL_DEFAULT, source: 'default' } } : {},
    result: {
      share_url: `${PUBLIC_ORIGIN}/secret/${sec.identifier}`,
      receipt_url: rec?.identifier ? `${PUBLIC_ORIGIN}/receipt/${rec.identifier}` : null,
      burns_on_view: true, has_passphrase: Boolean(pass), expires_at: expires,
      recipient_needs: 'Only a web browser. No account, no payment.',
    },
    summary: `One-time link ready: it shows the secret once, then deletes it, or expires at ${expires}.`,
    next_steps: [{ action: 'Send share_url to the recipient. If you set a passphrase, give it to them another way.' }, { action: 'Open receipt_url to see whether it was viewed, or to burn it early.' }],
    disclaimer: 'The link works once. Anyone holding it can view the secret, so send it only to the intended recipient.',
  });
}

async function toolRequest(req, res, url) {
  const item = 'request';
  const p = await inputs(req, url);
  const extra = onlyKeys(p, ['ttl_hours', 'label']);
  if (extra.length) return err(res, 400, item, 'unknown_parameter', `Unknown input: ${extra.join(', ')}.`, 'Send only ttl_hours and label.', { accepts: ['ttl_hours', 'label'] });
  const ttl = ttlFrom(p.ttl_hours);
  if (ttl.bad) return err(res, 400, item, 'bad_value', `ttl_hours must be a whole number from ${TTL_MIN} to ${TTL_MAX}.`, `Use ${TTL_MIN}-${TTL_MAX}, or leave it out for ${TTL_DEFAULT}.`);
  const label = typeof p.label === 'string' ? p.label.trim().slice(0, 80) : '';
  const handle = 'REQ-' + rand(24), senderToken = rand(24), sec = ttl.value * 3600, expires = isoIn(sec);
  const rec = { status: 'waiting', label, created_at: nowIso(), expires_at: expires, h: sha(handle) };
  await store.set(`sse:req:${sha(handle)}`, JSON.stringify(rec), sec);
  await store.set(`sse:in:${sha(senderToken)}`, JSON.stringify({ h: sha(handle), label, expires_at: expires }), sec);
  send(res, 200, {
    ok: true, item: 'secure-secret-request', answer_type: 'action', as_of: nowIso(),
    inputs: { ...(p.ttl_hours !== undefined ? { ttl_hours: ttl.value } : {}), ...(label ? { label } : {}) },
    defaulted_inputs: ttl.defaulted ? { ttl_hours: { value: TTL_DEFAULT, source: 'default' } } : {},
    result: {
      request_url: `${PUBLIC_ORIGIN}/in/${senderToken}`,
      request_handle: handle, expires_at: expires,
      sender_needs: 'Only a web browser. No account, no payment.',
      sender_instructions: 'Open the request link, paste the secret, press Send. The link accepts one submission.',
      retrieve_with: { direct_url: `${PUBLIC_ORIGIN}/api/retrieve`, method: 'POST', body: { request_handle: handle }, poll_every_seconds: 15, tool_for_single_check: 'Secure Secrets Exchange: retrieve (free)' },
    },
    summary: `Request link ready until ${expires}. Send request_url to the sender; keep request_handle private and poll the free direct_url with it.`,
    next_steps: [{ action: 'Send request_url to the person or agent who has the secret.' }, { action: 'Poll the free direct_url in retrieve_with every 15 seconds or more until status is "delivered". It needs no account and uses no Qatom transactions.' }],
    disclaimer: 'Keep request_handle private: whoever holds it can retrieve the secret once.',
  });
}

async function toolRetrieve(req, res, url) {
  const item = 'retrieve';
  const p = await inputs(req, url);
  const extra = onlyKeys(p, ['request_handle']);
  if (extra.length) return err(res, 400, item, 'unknown_parameter', `Unknown input: ${extra.join(', ')}.`, 'Send only request_handle.');
  const handle = typeof p.request_handle === 'string' ? p.request_handle.trim() : '';
  if (!/^REQ-[A-Za-z0-9_-]{32}$/.test(handle)) return err(res, 400, item, 'handle_required', 'request_handle is required: the REQ-... value from the request tool.', 'Call again with the request_handle you were given.');
  if (await limited(`ret:${clientIp(req)}`, 120, 60)) return err(res, 429, item, 'slow_down', 'Too many retrieve calls.', 'Wait a minute, then poll every 15 seconds or more.');
  const key = `sse:req:${sha(handle)}`;
  const raw = await store.get(key);
  const base = { item: 'secure-secret-retrieve', answer_type: 'current', as_of: nowIso(), inputs: { request_handle: handle } };
  if (!raw) return send(res, 200, { ok: false, ...base, result: { status: 'not_found_or_expired' }, error: { code: 'not_found_or_expired', message: 'No open request with that handle. It may have expired, or the secret was already retrieved.', next_step: 'Create a new request if you still need the secret.' } });
  const rec = JSON.parse(raw);
  if (rec.status === 'waiting') return send(res, 200, { ok: true, ...base, result: { status: 'waiting', label: rec.label || null, expires_at: rec.expires_at }, summary: 'Nothing sent yet. Check again shortly; retrieving is free.', next_steps: [{ action: 'Call retrieve again in 15 seconds or more.' }] });
  const taken = await store.getdel(key);
  if (!taken) return send(res, 200, { ok: false, ...base, result: { status: 'already_retrieved' }, error: { code: 'already_retrieved', message: 'This secret was already retrieved.', next_step: 'Create a new request if you need it again.' } });
  const t = JSON.parse(taken);
  let payload;
  try { payload = open(t.ct); } catch { return err(res, 500, item, 'internal_error', 'The stored secret could not be decrypted.', 'Create a new request.'); }
  send(res, 200, { ok: true, ...base, result: { status: 'delivered', payload, note: t.note || null, label: t.label || null, received_at: t.received_at, e2e: isE2E(payload), ...(isE2E(payload) ? { decrypt_with: 'the key you appended to request_url after #; format in llms.txt (sse-e2e-v1)' } : {}) }, summary: isE2E(payload) ? 'Encrypted secret delivered. Decrypt it with your key; the server never had the key. It has now been deleted from the server.' : 'Secret delivered. It has now been deleted from the server; store it safely.', disclaimer: 'This was a one-time retrieval. The secret no longer exists on Secure Secrets Exchange.' });
}

// ---------- sender page (free, no account) ----------
function page(title, inner) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)} - ${NAME}</title>
<style>:root{--fg:#0f1d1c;--mut:#4b5b59;--line:#d7e0df;--acc:#0e6b62;--bg:#fff}@media(prefers-color-scheme:dark){:root{--fg:#e8efee;--mut:#9fb0ae;--line:#2b3a39;--acc:#4fbfb2;--bg:#0f1514}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:560px;margin:0 auto;padding:40px 16px}
h1{font-size:1.4rem;margin:0 0 8px}p{color:var(--mut)}label{display:block;font-weight:600;margin:16px 0 6px}textarea,input{width:100%;box-sizing:border-box;border:1px solid var(--line);border-radius:10px;padding:12px;font:inherit;background:transparent;color:inherit}
textarea{min-height:140px;font-family:ui-monospace,Menlo,monospace}button{margin-top:18px;background:var(--acc);color:#fff;border:0;border-radius:10px;padding:12px 18px;font:inherit;font-weight:600;cursor:pointer}.brand{font-size:.85rem;color:var(--mut);margin-bottom:24px}.ok{border:1px solid var(--line);border-radius:12px;padding:16px}.small{font-size:.85rem}a{color:var(--acc)}table{border-collapse:collapse;width:100%;font-size:.92rem}td,th{border-top:1px solid var(--line);padding:8px 6px;text-align:left;vertical-align:top}code{font-family:ui-monospace,Menlo,monospace;font-size:.85em;word-break:break-all}</style></head>
<body><main><div class="brand">${NAME}</div>${inner}</main></body></html>`;
}
async function senderPage(req, res, token) {
  const key = `sse:in:${sha(token)}`;
  const raw = await store.get(key);
  if (!raw) return send(res, 404, page('Link not available', '<h1>This link is no longer available</h1><p>It has already been used or has expired. Ask the requester for a new link.</p>'), 'text/html; charset=utf-8');
  const meta = JSON.parse(raw);
  if (req.method === 'GET') {
    return send(res, 200, page('Send a secret', `<h1>Send a secret securely</h1><p>${meta.label ? `Requested for: <strong>${esc(meta.label)}</strong>. ` : ''}Paste it below. It is encrypted, can be collected only once by the requester, and is deleted after that. This link works once and expires ${esc(meta.expires_at)}.</p>
<p id="e2e" hidden><strong>End-to-end encrypted:</strong> your browser encrypts the secret before sending it. The server never sees it in plain text.</p>
<form id="f" method="post" autocomplete="off"><label for="s">Secret</label><textarea id="s" name="secret" required maxlength="${MAX_PAYLOAD}" spellcheck="false"></textarea>
<label for="n">Note for the requester (optional)</label><input id="n" name="note" maxlength="200"><button type="submit">Send securely</button></form>
<p class="small">How this works and what we can and cannot see: <a href="/security">security</a>.</p><script>${SENDER_JS}</script>`), 'text/html; charset=utf-8', { 'content-security-policy': `default-src 'none'; script-src ${cspHash(SENDER_JS)}; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` });
  }
  if (req.method !== 'POST') return notFound(res);
  if (await limited(`in:${clientIp(req)}`, 30, 3600)) return send(res, 429, page('Slow down', '<h1>Too many attempts</h1><p>Please try again later.</p>'), 'text/html; charset=utf-8');
  let p; try { p = await inputs(req, new URL('http://x/')); } catch { return send(res, 400, page('Not sent', '<h1>Not sent</h1><p>The form could not be read. Go back and try again.</p>'), 'text/html; charset=utf-8'); }
  const secret = typeof p.secret === 'string' ? p.secret : '';
  const e2e = isE2E(secret);
  if (!secret.trim() || (e2e ? !e2eValid(secret) : secret.length > MAX_PAYLOAD)) return send(res, 400, page('Not sent', `<h1>Not sent</h1><p>Paste a secret of up to ${MAX_PAYLOAD} characters and try again.</p>`), 'text/html; charset=utf-8');
  const claimed = await store.getdel(key);
  if (!claimed) return send(res, 410, page('Link not available', '<h1>This link was already used</h1><p>Ask the requester for a new link.</p>'), 'text/html; charset=utf-8');
  const reqKey = `sse:req:${meta.h}`;
  const left = await store.ttl(reqKey);
  if (left <= 0) return send(res, 410, page('Link expired', '<h1>This request has expired</h1><p>Ask the requester for a new link.</p>'), 'text/html; charset=utf-8');
  await store.set(reqKey, JSON.stringify({ status: 'delivered', ct: seal(secret), note: typeof p.note === 'string' ? p.note.slice(0, isE2E(p.note) ? 400 : 200) : '', label: meta.label, received_at: nowIso() }), left);
  send(res, 200, page('Sent', '<div class="ok"><h1>Sent securely</h1><p>The requester can now collect it, once. You can close this page.</p></div>'), 'text/html; charset=utf-8');
}

// ---------- free storefront items ----------
async function feedback(req, res, url) {
  const p = await inputs(req, url);
  const extra = onlyKeys(p, ['message', 'from_email', 'subject_ref']);
  if (extra.length) return err(res, 400, 'feedback', 'unknown_parameter', `Unknown input: ${extra.join(', ')}.`, 'Send message, and optionally from_email and subject_ref.');
  const message = typeof p.message === 'string' ? p.message.trim() : '';
  if (message.length < 3 || message.length > 2000) return err(res, 400, 'feedback', 'bad_value', 'message must be 3 to 2000 characters.', 'Write a short message and try again.');
  if (await limited(`fb:all`, 30, 3600)) return err(res, 429, 'feedback', 'slow_down', 'Feedback is busy right now.', 'Try again in an hour.');
  const ref = 'SSE-FB-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  await store.lpush('sse:feedback', JSON.stringify({ ref, at: nowIso(), message, from_email: typeof p.from_email === 'string' ? p.from_email.slice(0, 200) : null, subject_ref: typeof p.subject_ref === 'string' ? p.subject_ref.slice(0, 120) : null }), 500);
  send(res, 200, { ok: true, item: 'secure-secrets-feedback', answer_type: 'action', as_of: nowIso(), result: { reference: ref }, summary: `Thanks. Your message was received (reference ${ref}).` });
}
async function inbox(req, res) {
  if (!INBOX_TOKEN || !same(req.headers['authorization'] || '', `Bearer ${INBOX_TOKEN}`)) return notFound(res);
  send(res, 200, { feedback: (await store.lrange('sse:feedback', 100)).map((s) => JSON.parse(s)) });
}
function status(res) {
  send(res, 200, {
    ok: true, item: 'secure-secrets-status', answer_type: 'current', as_of: nowIso(), service: NAME,
    result: {
      up: true,
      tools: {
        create: { price_usd_tdn: PRICE.create, inputs: { payload: `string, required: the secret (standard, up to ${MAX_PAYLOAD} characters) or an end-to-end ciphertext starting "${E2E_PREFIX}" (up to ${E2E_MAX})`, ttl_hours: `integer ${TTL_MIN}-${TTL_MAX}, default ${TTL_DEFAULT}`, passphrase: 'string, optional, up to 128 characters, standard mode only' }, returns: 'share_url (one view, browser only), receipt_url, expires_at; in end-to-end mode share_url_base to which you append #key' },
        request: { price_usd_tdn: PRICE.request, inputs: { ttl_hours: `integer ${TTL_MIN}-${TTL_MAX}, default ${TTL_DEFAULT}`, label: 'string, optional, shown to the sender, up to 80 characters' }, returns: 'request_url for the sender, request_handle for you, expires_at' },
        retrieve: { price_usd_tdn: PRICE.retrieve, inputs: { request_handle: 'string, required, REQ-...' }, returns: 'status waiting | delivered (payload once, then deleted)', direct_url: `${PUBLIC_ORIGIN}/api/retrieve` },
      },
      recipients_and_senders_need: 'A web browser only. No account, no payment.',
      modes: { e2e: `recommended; format ${E2E_PREFIX}base64url(iv12 + AES-256-GCM ciphertext + tag16); key only in the link fragment`, standard: 'for agents that cannot run code; the operator can read secrets while stored' },
      security: { page: `${PUBLIC_ORIGIN}/security`, security_txt: `${PUBLIC_ORIGIN}/.well-known/security.txt`, ...integrity() },
      read_me: `${PUBLIC_ORIGIN}/llms.txt`,
    },
    summary: `${NAME} is up. Creating a link or a request costs 0.100 USD-TDN; retrieving is free.`,
  });
}
function llms(res) {
  const ids = (k) => (ITEM_IDS[k] ? ` (item ${ITEM_IDS[k]})` : '');
  send(res, 200, `# ${NAME}

> One-time secret links for AI agents and the people they work with. Send a secret (an API key, token or password) as a link that shows it once and then deletes it, or ask someone to send you one through a private link. End-to-end mode: if you can run code, encrypt the secret yourself and keep the key in the link's #fragment, so neither this service, Qatom nor Cloudflare ever sees it. Creating a link or a request costs 0.100 USD-TDN per call on Qatom; retrieving is free. Recipients and senders need only a web browser: no account, no payment. Security and how to verify it: ${PUBLIC_ORIGIN}/security

Generated: ${nowIso()}. This file is generated by the service.

## How to call

From the Qatom master MCP (https://mcp.m.todaq.net): \`catalog_search\` for "Secure Secrets Exchange", then \`agent_checkout\` with the item id and the arguments below.

| Tool | Price (USD-TDN) | Inputs | Returns |
|---|---|---|---|
| Secure Secrets Exchange: create${ids('create')} | ${PRICE.create} | payload (required: the secret, or an end-to-end ciphertext), ttl_hours (1-168, default 168), passphrase (optional, standard mode only) | share_url (one view), receipt_url, expires_at; end-to-end: share_url_base + #key |
| Secure Secrets Exchange: request${ids('request')} | ${PRICE.request} | ttl_hours (1-168, default 168), label (optional, shown to the sender) | request_url (for the sender), request_handle (for you), expires_at |
| Secure Secrets Exchange: retrieve${ids('retrieve')} | free | request_handle (required) | status waiting, or delivered with payload (once, then deleted) |
| Secure Secrets Exchange: feedback${ids('feedback')} | free | message (required), from_email, subject_ref | a reference id |

Free check, no Qatom needed: ${PUBLIC_ORIGIN}/status

## Worked examples

1. Send a secret: create with {"payload": "sk-live-...", "ttl_hours": 24}. Give share_url to the recipient. It opens once in any browser, then the secret is gone.
2. Send with a passphrase: create with {"payload": "...", "passphrase": "blue-otter"}. Tell the recipient the passphrase another way.
3. Collect a secret: request with {"label": "Stripe test key for Acme"}. Send request_url to the person who has it. Then check for it at the direct URL below every 15 seconds or more: "waiting" until they press Send, then "delivered" with the payload, once.
4. Poll at the direct URL, not through Qatom: POST ${PUBLIC_ORIGIN}/api/retrieve with {"request_handle": "REQ-..."}. It is free, needs no account and does not count against anyone's Qatom transactions. The free retrieve item does the same thing in one Qatom call; use it for a single check, not for polling.

## End-to-end mode (recommended when you can run code)

The secret is encrypted by you before you buy, and decrypted only in the recipient's browser (or by you, for requests). The key travels only after # in a link; browsers never send that part to a server. This service, Qatom and Cloudflare see ciphertext only.

Format (sse-e2e-v1): key = 32 random bytes, written base64url without padding (43 characters). iv = 12 random bytes. payload = "${E2E_PREFIX}" + base64url(iv + AES-256-GCM ciphertext + 16-byte tag), no padding, no associated data, plaintext UTF-8. At most ${E2E_MAX} characters.

Send a secret end-to-end:
1. Encrypt (Python, package cryptography):
   import os, base64; from cryptography.hazmat.primitives.ciphers.aead import AESGCM
   b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
   key = AESGCM.generate_key(bit_length=256); iv = os.urandom(12)
   payload = "${E2E_PREFIX}" + b64u(iv + AESGCM(key).encrypt(iv, secret.encode(), None))
2. Buy create with {"payload": payload}. The answer has mode "e2e" and share_url_base.
3. Give the recipient share_url_base + "#" + b64u(key). Their browser fetches the ciphertext once, deletes it on the server, and decrypts locally.
4. Optional: GET receipt_url shows waiting, viewed, burned or expired; POST {"action": "burn"} to it deletes the secret early. Free.

Collect a secret end-to-end:
1. Make a key as above. Buy request as usual.
2. Give the sender request_url + "#" + b64u(key). Their browser encrypts before sending (the page shows "End-to-end encrypted").
3. Poll the free direct retrieve URL. When delivered, payload starts with "${E2E_PREFIX}" and e2e is true. Decrypt:
   raw = base64.urlsafe_b64decode(payload[len("${E2E_PREFIX}"):] + "=" * (-len(payload[len("${E2E_PREFIX}"):]) % 4))
   secret = AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()
   A note from the sender, if any, is encrypted the same way.

Node 20 or later (built-in WebCrypto): key = crypto.getRandomValues(new Uint8Array(32)); iv = crypto.getRandomValues(new Uint8Array(12)); ct = new Uint8Array(await crypto.subtle.encrypt({name: "AES-GCM", iv}, await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]), new TextEncoder().encode(secret))); payload = "${E2E_PREFIX}" + Buffer.concat([iv, ct]).toString("base64url"); link fragment = Buffer.from(key).toString("base64url").

If you cannot run code, use standard mode (send the secret as payload). It works the same way for the recipient, but the operator could read it while it is stored.

## Security

- Who sees what, how it is stored and deleted, and what is logged: ${PUBLIC_ORIGIN}/security
- The browser pages each run one inline script whose SHA-256 is pinned in the page's Content-Security-Policy. Current hashes: viewer ${hexHash(VIEWER_JS)}, sender ${hexHash(SENDER_JS)}. Also at ${PUBLIC_ORIGIN}/status. Check that they match the published source.
- Gateway source: ${SOURCE_URL}. Secrets core: ${CORE_SOURCE_URL} (MIT), version ${CORE_VERSION}.
- Report a problem: ${PUBLIC_ORIGIN}/.well-known/security.txt

## Responses

Every answer has ok, item, answer_type, as_of, inputs (secrets are never echoed), result, summary and next_steps. Errors carry error.code, a plain message and a next step:
- payload_required (400), payload_too_large (413), bad_value (400, with the accepted range), unknown_parameter (400)
- end-to-end: bad_value (400) for a malformed ciphertext or a passphrase; the viewer's reveal call returns not_available (404) once opened, burned or expired
- handle_required (400), not_found_or_expired and already_retrieved (200 with ok: false and result.status set, so agents see the reason), slow_down (429), internal_error (500/502)

## For agents and for people

- Agents call the tools. Send share_url and request_url to people; keep request_handle and receipt_url to yourself.
- A secret sent with create can be viewed once; after that, or at expiry, it is deleted.
- A request accepts one submission; retrieving it deletes it.
- In standard mode, payloads pass through Qatom's call to this service and are stored encrypted (with a server-held key) until viewed or retrieved. In end-to-end mode only ciphertext ever leaves you. Either way, do not use it for long-lived master credentials; rotate anything important after handing it over.

## Refunds

Refunds are given on request. Send the free feedback item a message quoting the transaction id of the purchase (each item in a cart has its own), and say what went wrong. A refund is sent back to the wallet that paid. If there is no reply within two days, call the free Team Kepler feedback item (catalog item 194) or email support@todaq.net.

## Resources

- Status: ${PUBLIC_ORIGIN}/status
- Feedback, refunds and questions: the free "Secure Secrets Exchange: feedback" item, or support@todaq.net
- Built on an open-source secrets core (MIT License, (c) 2012-ongoing delano, contributors), with Qatom per-call tools added.
`, 'text/plain; charset=utf-8');
}

// ---------- end-to-end mode (sse-e2e-v1): the buyer encrypts; the key travels only in the link's #fragment ----------
async function createE2E(res, p, payload) {
  const item = 'create';
  if (!e2eValid(payload)) return err(res, 400, item, 'bad_value', `An end-to-end payload must be "${E2E_PREFIX}" followed by base64url(iv[12] + AES-256-GCM ciphertext + tag[16]), at most ${E2E_MAX} characters.`, `See ${PUBLIC_ORIGIN}/llms.txt, section End-to-end mode.`);
  if (typeof p.passphrase === 'string' && p.passphrase.length) return err(res, 400, item, 'bad_value', 'passphrase is not used in end-to-end mode: the key after # in the link already protects the secret.', 'Call again without passphrase.');
  const ttl = ttlFrom(p.ttl_hours);
  if (ttl.bad) return err(res, 400, item, 'bad_value', `ttl_hours must be a whole number from ${TTL_MIN} to ${TTL_MAX}.`, `Use ${TTL_MIN}-${TTL_MAX}, or leave it out for ${TTL_DEFAULT}.`, { accepts: [{ input: 'ttl_hours', unit: 'hours', range: [TTL_MIN, TTL_MAX] }] });
  const id = rand(24), rtoken = rand(24), sec = ttl.value * 3600, expires = isoIn(sec);
  await store.set(`sse:e2e:${sha(id)}`, JSON.stringify({ ct: payload, expires_at: expires }), sec);
  await store.set(`sse:e2er:${sha(rtoken)}`, JSON.stringify({ h: sha(id), expires_at: expires }), sec + 7 * 86400);
  send(res, 200, {
    ok: true, item: 'secure-secret-create', answer_type: 'action', as_of: nowIso(),
    inputs: { payload: `[end-to-end ciphertext, ${payload.length} characters, not echoed]`, ...(p.ttl_hours !== undefined ? { ttl_hours: ttl.value } : {}) },
    defaulted_inputs: ttl.defaulted ? { ttl_hours: { value: TTL_DEFAULT, source: 'default' } } : {},
    result: {
      mode: 'e2e',
      share_url_base: `${PUBLIC_ORIGIN}/v/${id}`,
      share_url: `${PUBLIC_ORIGIN}/v/${id}#<YOUR_KEY>`,
      how_to_share: 'Replace <YOUR_KEY> with your base64url key (43 characters). The key never reaches this server: browsers do not send the part after #.',
      receipt_url: `${PUBLIC_ORIGIN}/api/e2e/receipt/${rtoken}`,
      burns_on_view: true, expires_at: expires,
      recipient_needs: 'Only a web browser. No account, no payment. The browser decrypts locally.',
    },
    summary: `End-to-end link ready until ${expires}: add your key after # and send it. The server holds only ciphertext and deletes it on first view.`,
    next_steps: [{ action: 'Send share_url_base + "#" + your key to the recipient.' }, { action: 'GET receipt_url to see whether it was viewed; POST {"action":"burn"} to it to delete it early.' }],
    disclaimer: 'Anyone holding the full link (with the key) can view the secret once. Keep the key out of logs and send the link only to the intended recipient.',
  });
}
function viewerPage(res) {
  send(res, 200, page('Secret', `<h1>Someone sent you a secret</h1><p>It is end-to-end encrypted. Your browser will download the encrypted copy and decrypt it here with the key in this link. It can be opened once; after that it is gone.</p>
<button id="go" type="button">Reveal the secret</button><p id="st" role="status"></p><textarea id="out" hidden readonly spellcheck="false" aria-label="Secret"></textarea>
<p class="small">How this works and what we can and cannot see: <a href="/security">security</a>.</p><script>${VIEWER_JS}</script>`), 'text/html; charset=utf-8',
  { 'content-security-policy': `default-src 'none'; script-src ${cspHash(VIEWER_JS)}; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` });
}
async function e2eReveal(req, res, id) {
  if (await limited(`e2e:${clientIp(req)}`, 60, 60)) return err(res, 429, 'view', 'slow_down', 'Too many attempts.', 'Wait a minute and try again.');
  const raw = await store.getdel(`sse:e2e:${sha(id)}`);
  if (!raw) return err(res, 404, 'view', 'not_available', 'This secret is no longer available. It was already opened, burned, or it expired.', 'Ask the sender for a new link.');
  await store.set(`sse:e2ev:${sha(id)}`, nowIso(), 7 * 86400);
  send(res, 200, { ok: true, item: 'secure-secret-view', result: { ciphertext: JSON.parse(raw).ct } });
}
async function e2eReceipt(req, res, url, rtoken) {
  const raw = await store.get(`sse:e2er:${sha(rtoken)}`);
  if (!raw) return notFound(res);
  const r = JSON.parse(raw);
  if (req.method === 'POST') {
    let p; try { p = await inputs(req, url); } catch { p = {}; }
    if (p.action !== 'burn') return err(res, 400, 'receipt', 'bad_value', 'POST {"action":"burn"} to delete the secret early.', 'Send action "burn", or GET to check status.');
    const gone = await store.getdel(`sse:e2e:${r.h}`);
    if (gone) await store.set(`sse:e2eb:${r.h}`, nowIso(), 7 * 86400);
    return send(res, 200, { ok: true, item: 'secure-secret-receipt', result: { status: gone ? 'burned' : 'already_gone' }, summary: gone ? 'Burned: the encrypted copy is deleted.' : 'Nothing to burn: it was already viewed, burned or expired.' });
  }
  const [live, viewed, burned] = await Promise.all([store.get(`sse:e2e:${r.h}`), store.get(`sse:e2ev:${r.h}`), store.get(`sse:e2eb:${r.h}`)]);
  const st = live ? 'waiting' : viewed ? 'viewed' : burned ? 'burned' : 'expired';
  send(res, 200, { ok: true, item: 'secure-secret-receipt', answer_type: 'current', as_of: nowIso(), result: { status: st, ...(viewed ? { viewed_at: viewed } : {}), expires_at: r.expires_at }, summary: { waiting: 'Not opened yet.', viewed: `Opened at ${viewed}; the encrypted copy is deleted.`, burned: 'Burned before anyone opened it.', expired: 'Expired unopened; deleted.' }[st] });
}

// ---------- security page and security.txt ----------
function integrity() {
  return {
    viewer_script_sha256: hexHash(VIEWER_JS), viewer_script_csp: cspHash(VIEWER_JS),
    sender_script_sha256: hexHash(SENDER_JS), sender_script_csp: cspHash(SENDER_JS),
    core_version: CORE_VERSION, gateway_source: SOURCE_URL, core_source: CORE_SOURCE_URL,
  };
}
function securityPage(res) {
  const i = integrity();
  send(res, 200, page('Security', `<h1>How ${NAME} keeps secrets</h1>
<p>One-time links for passwords, API keys and tokens, for AI agents and the people they work with. A link shows its secret once, then the secret is deleted. Recipients and senders need only a browser.</p>
<p>There are two modes. <strong>End-to-end</strong> is the one to use when it matters: the secret is encrypted before it leaves the buyer's agent, and the key travels only in the part of the link after <code>#</code>, which browsers never send to a server. <strong>Standard</strong> is simpler, for agents that cannot run code, and asks you to trust the operator.</p>
<h2>Who can see the secret</h2>
<table><tr><th></th><th>End-to-end</th><th>Standard</th></tr>
<tr><td>This service (server and operator)</td><td>No: ciphertext only</td><td>Yes, while stored</td></tr>
<tr><td>Qatom (payment rail)</td><td>No: ciphertext only</td><td>Passes through in the purchase call</td></tr>
<tr><td>Cloudflare (TLS and tunnel)</td><td>No: ciphertext only</td><td>Yes, in transit</td></tr>
<tr><td>The buyer's AI provider</td><td colspan="2">Yes, if the secret was in the agent's conversation. Outside our control.</td></tr>
<tr><td>The recipient</td><td colspan="2">Yes, once.</td></tr></table>
<h2>What happens to it</h2>
<ul>
<li><strong>End-to-end links:</strong> we store the ciphertext only, until first view, a burn or expiry (1 to 168 hours). Opening it deletes it on the server, then the recipient's browser decrypts it.</li>
<li><strong>End-to-end requests:</strong> the requester's agent adds a key after <code>#</code> in the request link. The sender's browser encrypts before sending. The requester decrypts after retrieving.</li>
<li><strong>Standard links:</strong> stored encrypted at rest by the open-source secrets core, with a key held on the server. Deleted on first view or expiry.</li>
<li><strong>Standard requests:</strong> sealed with AES-256-GCM using a key held on the server. Deleted on retrieval or expiry.</li>
<li><strong>Logs:</strong> the gateway logs the tool name and the Qatom transaction id. It never logs secrets, handles, keys or links.</li>
</ul>
<h2>Check it yourself</h2>
<ul>
<li>Open a link twice. The second time it is gone. A request link accepts one submission, and a second retrieve says <code>already_retrieved</code>.</li>
<li>Read the browser code. The viewer page and the sender page each run one inline script. Its SHA-256 is pinned in the page's Content-Security-Policy header, so the browser refuses any other script. Compare the hashes below with the published source.<br>
Viewer script: <code>${i.viewer_script_sha256}</code><br>Sender script: <code>${i.sender_script_sha256}</code></li>
<li>Read the code: gateway <a href="${i.gateway_source}">${esc(i.gateway_source.replace('https://', ''))}</a>. The secrets core is the open-source project at <a href="${i.core_source}">${esc(i.core_source.replace('https://', ''))}</a> (MIT), version <code>${esc(i.core_version)}</code>.</li>
<li>Machine-readable: <a href="/status">/status</a>, <a href="/llms.txt">/llms.txt</a> (End-to-end mode and Security sections), <a href="/.well-known/security.txt">security.txt</a>.</li>
</ul>
<h2>Limits</h2>
<ul>
<li>Nobody outside can prove that the code running here is the published code. End-to-end mode is built so that this does not matter for the secret itself: the server never gets the key. A tampered page would show a different script hash.</li>
<li>Anyone holding a full link can open it once. Send it only to the intended person.</li>
<li>Do not use this for long-lived master credentials. Rotate anything important after handing it over.</li>
</ul>
<h2>Report a problem</h2>
<p>Use the contact in <a href="/.well-known/security.txt">security.txt</a>, or the free "Secure Secrets Exchange: send feedback" item on Qatom. Never include a secret.</p>`), 'text/html; charset=utf-8', { 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" });
}
function securityTxt(res) {
  const exp = new Date(Date.now() + 300 * 86400 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  send(res, 200, `Contact: ${SECURITY_CONTACT}
Expires: ${exp}
Preferred-Languages: en
Canonical: ${PUBLIC_ORIGIN}/.well-known/security.txt
Policy: ${PUBLIC_ORIGIN}/security
`, 'text/plain; charset=utf-8');
}

// ---------- router ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://local');
  const path = url.pathname;
  try {
    if (path === '/status' && req.method === 'GET') return status(res);
    if ((path === '/' || path === '/security') && req.method === 'GET') return securityPage(res);
    if (path === '/.well-known/security.txt' && req.method === 'GET') return securityTxt(res);
    if (path === '/llms.txt' && req.method === 'GET') return llms(res);
    if (path === '/api/retrieve' && (req.method === 'POST' || req.method === 'GET')) return await toolRetrieve(req, res, url);
    if (path === '/api/feedback' && req.method === 'POST') return await feedback(req, res, url);
    if (path === '/api/inbox' && req.method === 'GET') return await inbox(req, res);
    let m;
    if ((m = path.match(/^\/in\/([A-Za-z0-9_-]{32})$/))) return await senderPage(req, res, m[1]);
    if ((m = path.match(/^\/v\/([A-Za-z0-9_-]{32})$/)) && req.method === 'GET') return viewerPage(res);
    if ((m = path.match(/^\/api\/e2e\/reveal\/([A-Za-z0-9_-]{32})$/)) && req.method === 'POST') return await e2eReveal(req, res, m[1]);
    if ((m = path.match(/^\/api\/e2e\/receipt\/([A-Za-z0-9_-]{32})$/)) && (req.method === 'GET' || req.method === 'POST')) return await e2eReceipt(req, res, url, m[1]);
    if (SERVICE_PATH && (m = path.match(/^\/paid\/([^/]+)\/(create|request)$/)) && (req.method === 'POST' || req.method === 'GET')) {
      if (!same(m[1], SERVICE_PATH) || !paidOk(req)) return notFound(res);
      const tx = req.headers['x-qatom-transaction-id'];
      console.log(JSON.stringify({ at: nowIso(), tool: m[2], tx: tx || null }));
      return m[2] === 'create' ? await toolCreate(req, res, url) : await toolRequest(req, res, url);
    }
    return notFound(res);
  } catch (e) {
    if (e.tooLarge) return err(res, 413, 'request', 'payload_too_large', 'The request body is too large.', `Keep secrets under ${MAX_PAYLOAD} characters.`);
    if (e.badJson) return err(res, 400, 'request', 'bad_json', 'The request body is not valid JSON.', 'Send a JSON object.');
    console.error(e);
    return err(res, 500, 'request', 'internal_error', 'Something went wrong.', 'Try again in a minute.');
  }
});
server.listen(PORT, () => console.log(`${NAME} gateway on :${PORT}`));
