// Local test: fake secrets core + the gateway (memory store, or Valkey when REDIS_URL is set).
import http from 'node:http';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';

const CORE_PORT = 18300, GW_PORT = 18301, SP = 'testservicepath', TOK = 'testfulfilmenttoken';
let lastConceal = null;
const core = http.createServer((req, res) => {
  let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => {
    if (req.url === '/api/v2/secret/conceal' && req.headers.authorization === 'Basic ' + Buffer.from('svc@x:tok').toString('base64')) {
      lastConceal = JSON.parse(b);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ success: true, record: { secret: { identifier: 'sec123' }, receipt: { identifier: 'rec456' } } }));
    } else { res.writeHead(401); res.end('{}'); }
  });
}).listen(CORE_PORT);

const gw = spawn(process.execPath, ['server.mjs'], { env: { ...process.env, PORT: String(GW_PORT), CORE_URL: `http://127.0.0.1:${CORE_PORT}`, CORE_API_USER: 'svc@x', CORE_API_TOKEN: 'tok', SERVICE_PATH: SP, QATOM_FULFILMENT_TOKEN: TOK, INBOX_TOKEN: 'inbox', GATEWAY_KEY: 'k'.repeat(40), PUBLIC_ORIGIN: 'https://secrets.example' }, stdio: ['ignore', 'pipe', 'inherit'] });
await new Promise((r) => gw.stdout.once('data', r));
const B = `http://127.0.0.1:${GW_PORT}`;
const post = (p, body, h = {}) => fetch(B + p, { method: 'POST', headers: { 'content-type': 'application/json', ...h }, body: JSON.stringify(body) });
const auth = { authorization: `Bearer ${TOK}` };
let n = 0; const ok = (m) => console.log(`ok ${++n} ${m}`);
try {
  let r = await fetch(B + '/status'); assert.equal(r.status, 200); ok('status 200');
  r = await fetch(B + '/llms.txt'); assert.match(await r.text(), /Secure Secrets Exchange/); ok('llms.txt');
  r = await post(`/paid/${SP}/create`, { payload: 'x' }); assert.equal(r.status, 404); ok('create without header 404');
  r = await post(`/paid/wrong/create`, { payload: 'x' }, auth); assert.equal(r.status, 404); ok('create wrong path 404');
  r = await post(`/paid/${SP}/create`, { payload: 'sk-test-123', ttl_hours: 24, passphrase: 'pp' }, auth);
  let j = await r.json(); assert.equal(r.status, 200); assert.equal(j.result.share_url, 'https://secrets.example/secret/sec123');
  assert.equal(lastConceal.secret.ttl, 86400); assert.equal(lastConceal.secret.passphrase, 'pp');
  assert.ok(!JSON.stringify(j).includes('sk-test-123') && !JSON.stringify(j).includes('"pp"')); ok('create ok, secret and passphrase not echoed');
  r = await post(`/paid/${SP}/create`, { payload: 'x', ttl_hours: 500 }, auth); assert.equal(r.status, 400); ok('ttl out of range 400');
  r = await post(`/paid/${SP}/create`, { payload: 'x', foo: 1 }, auth); assert.equal(r.status, 400); assert.equal((await r.json()).error.code, 'unknown_parameter'); ok('unknown param 400');
  r = await post(`/paid/${SP}/create`, {}, auth); assert.equal((await r.json()).error.code, 'payload_required'); ok('payload required');
  r = await post(`/paid/${SP}/request`, { label: 'Acme key', ttl_hours: 2 }, auth); j = await r.json(); assert.equal(r.status, 200);
  const handle = j.result.request_handle, senderUrl = j.result.request_url; assert.match(handle, /^REQ-/); ok('request ok');
  const token = senderUrl.split('/in/')[1];
  r = await post('/api/retrieve', { request_handle: handle }); j = await r.json(); assert.equal(j.result.status, 'waiting'); ok('retrieve waiting (free, no header)');
  r = await fetch(`${B}/in/${token}`); assert.equal(r.status, 200); assert.match(await r.text(), /Acme key/); ok('sender page GET');
  r = await fetch(`${B}/in/${token}`); assert.equal(r.status, 200); ok('sender page GET twice still fine (link previews)');
  r = await fetch(`${B}/in/${token}`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'secret=hunter2%20%26%20more&note=from+bob' }); assert.equal(r.status, 200); ok('sender submits');
  r = await fetch(`${B}/in/${token}`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'secret=again' }); assert.ok([404, 410].includes(r.status)); ok('second submission refused');
  r = await post('/api/retrieve', { request_handle: handle }); j = await r.json(); assert.equal(j.result.status, 'delivered'); assert.equal(j.result.payload, 'hunter2 & more'); assert.equal(j.result.note, 'from bob'); ok('retrieve delivers payload');
  r = await post('/api/retrieve', { request_handle: handle }); assert.equal(r.status, 200); assert.equal((await r.json()).result.status, 'not_found_or_expired'); ok('second retrieve: 200 with status not_found_or_expired');
  r = await post('/api/retrieve', { request_handle: 'bad' }); assert.equal(r.status, 400); ok('bad handle 400');
  r = await post('/api/feedback', { message: 'hello there' }); j = await r.json(); assert.match(j.result.reference, /^SSE-FB-/); ok('feedback');
  r = await fetch(B + '/api/inbox', { headers: { authorization: 'Bearer inbox' } }); j = await r.json(); assert.equal(j.feedback[0].message, 'hello there'); ok('inbox');
  r = await fetch(B + '/api/inbox'); assert.equal(r.status, 404); ok('inbox needs token');
  // ---------- end-to-end mode ----------
  const { webcrypto } = await import('node:crypto');
  const b64u = (b) => Buffer.from(b).toString('base64url');
  const key = webcrypto.getRandomValues(new Uint8Array(32));
  const ck = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const enc = async (t) => { const iv = webcrypto.getRandomValues(new Uint8Array(12)); const c = new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, ck, new TextEncoder().encode(t))); return 'sse-e2e-v1.' + Buffer.concat([iv, c]).toString('base64url'); };
  const dec = async (p) => { const raw = Buffer.from(p.slice('sse-e2e-v1.'.length), 'base64url'); return new TextDecoder().decode(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.subarray(0, 12) }, ck, raw.subarray(12))); };
  const ctext = await enc('sk-e2e-secret');
  lastConceal = null;
  r = await post(`/paid/${SP}/create`, { payload: ctext, ttl_hours: 2 }, auth); j = await r.json(); assert.equal(r.status, 200); assert.equal(j.result.mode, 'e2e');
  assert.equal(lastConceal, null); assert.ok(!JSON.stringify(j).includes(ctext)); ok('e2e create: stored by gateway, core not called, ciphertext not echoed');
  const vid = j.result.share_url_base.split('/v/')[1], receipt = j.result.receipt_url.replace('https://secrets.example', B);
  r = await post(`/paid/${SP}/create`, { payload: 'sse-e2e-v1.!!bad', ttl_hours: 2 }, auth); assert.equal(r.status, 400); ok('e2e malformed ciphertext 400');
  r = await post(`/paid/${SP}/create`, { payload: ctext, passphrase: 'x' }, auth); assert.equal(r.status, 400); ok('e2e with passphrase 400');
  r = await fetch(`${B}/v/${vid}`); let html = await r.text(); const csp = r.headers.get('content-security-policy');
  const m1 = html.match(/<script>([\s\S]*)<\/script>/); const h1 = "'sha256-" + (await import('node:crypto')).createHash('sha256').update(m1[1], 'utf8').digest('base64') + "'";
  assert.ok(csp.includes(h1) && !html.includes(ctext)); ok('viewer page: CSP pins the inline script hash; no ciphertext in HTML');
  r = await fetch(receipt); assert.equal((await r.json()).result.status, 'waiting'); ok('e2e receipt waiting');
  assert.ok(html.includes('id="copy"') && html.includes('Copy to clipboard') && m1[1].includes('navigator.clipboard')); ok('viewer page has a Copy button wired to the clipboard');
  r = await fetch(`${B}/api/e2e/reveal/${vid}`, { method: 'OPTIONS' }); assert.equal(r.status, 204); assert.equal(r.headers.get('access-control-allow-origin'), '*'); ok('reveal preflight allows the in-chat app');
  r = await fetch(receipt); assert.equal(r.headers.get('access-control-allow-origin'), '*'); ok('receipt readable cross-origin');
  r = await fetch(`${B}/api/e2e/reveal/${vid}`, { method: 'POST' }); j = await r.json(); assert.equal(await dec(j.result.ciphertext), 'sk-e2e-secret'); ok('e2e reveal returns ciphertext that decrypts with the fragment key');
  r = await fetch(`${B}/api/e2e/reveal/${vid}`, { method: 'POST' }); assert.equal(r.status, 404); ok('e2e second reveal 404');
  r = await fetch(receipt); assert.equal((await r.json()).result.status, 'viewed'); ok('e2e receipt viewed');
  r = await post(`/paid/${SP}/create`, { payload: await enc('burn me') }, auth); j = await r.json();
  const rc2 = j.result.receipt_url.replace('https://secrets.example', B), vid2 = j.result.share_url_base.split('/v/')[1];
  r = await fetch(rc2, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"action":"burn"}' }); assert.equal((await r.json()).result.status, 'burned');
  r = await fetch(`${B}/api/e2e/reveal/${vid2}`, { method: 'POST' }); assert.equal(r.status, 404); r = await fetch(rc2); assert.equal((await r.json()).result.status, 'burned'); ok('e2e burn');
  // e2e request: sender page has pinned script; ciphertext submitted; retrieve flags e2e
  r = await post(`/paid/${SP}/request`, { label: 'e2e test' }, auth); j = await r.json();
  const h2 = j.result.request_handle, tok2 = j.result.request_url.split('/in/')[1];
  r = await fetch(`${B}/in/${tok2}`); html = await r.text(); const m2 = html.match(/<script>([\s\S]*)<\/script>/);
  const hh = "'sha256-" + (await import('node:crypto')).createHash('sha256').update(m2[1], 'utf8').digest('base64') + "'";
  assert.ok(r.headers.get('content-security-policy').includes(hh)); ok('sender page: CSP pins the inline script hash');
  const sct = await enc('db-password'), nct = await enc('from carol');
  r = await fetch(`${B}/in/${tok2}`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ secret: sct, note: nct }).toString() }); assert.equal(r.status, 200);
  r = await post('/api/retrieve', { request_handle: h2 }); j = await r.json(); assert.equal(j.result.e2e, true);
  assert.equal(await dec(j.result.payload), 'db-password'); assert.equal(await dec(j.result.note), 'from carol'); ok('e2e request round trip decrypts');
  r = await fetch(`${B}/security`); html = await r.text(); assert.ok(r.status === 200 && html.includes('End-to-end') && html.includes(m1[1] ? (await import('node:crypto')).createHash('sha256').update(m1[1], 'utf8').digest('hex') : 'x')); ok('security page lists the viewer script hash');
  r = await fetch(`${B}/`); assert.equal(r.status, 200); ok('root serves the security page');
  assert.ok(html.includes('In-chat app')); ok('security page explains the in-chat app');
  r = await fetch(`${B}/.well-known/security.txt`); const stxt = await r.text(); assert.ok(/^Contact: /m.test(stxt) && /^Expires: /m.test(stxt)); ok('security.txt has Contact and Expires');
  r = await fetch(`${B}/llms.txt`); const lt = await r.text(); assert.ok(lt.includes('## End-to-end mode') && lt.includes('## Security')); ok('llms.txt has End-to-end and Security sections');
  console.log(`all ${n} passed${process.env.REDIS_URL ? ' (Valkey store)' : ' (memory store)'}`);
} finally { gw.kill(); core.close(); }
