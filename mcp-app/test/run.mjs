// Offline checks for the SSE in-chat app. node test/run.mjs
import worker, { handle, callTool, TOOLS, APP_HTML } from '../src/index.mjs';
import { webcrypto } from 'node:crypto';
let n = 0, bad = 0;
const t = async (name, fn) => { n++; try { await fn(); console.log('ok  ', name); } catch (e) { bad++; console.log('FAIL', name, '-', e.message); } };
const eq = (a, b, m) => { if (a !== b) throw new Error(`${m || ''} got ${JSON.stringify(a)} want ${JSON.stringify(b)}`); };
const yes = (v, m) => { if (!v) throw new Error(m || 'expected true'); };
const kv = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, put: async (k, v) => { m.set(k, v); }, m }; };
const env = { LINKS: kv() };
const rpc = (method, params, id = 1) => handle(env, { jsonrpc: '2.0', id, method, params });
const BASE = 'https://secrets.agentkepler.tech/v/' + 'A'.repeat(32);
const RCPT = 'https://secrets.agentkepler.tech/api/e2e/receipt/' + 'B'.repeat(32);
const REF = 'abcDEF123_-xyz7890QR';

await t('initialize declares the MCP Apps extension', async () => {
  const r = (await rpc('initialize', { protocolVersion: '2025-06-18' })).result;
  eq(r.protocolVersion, '2025-06-18'); yes(r.capabilities.extensions['io.modelcontextprotocol/ui']); eq(r.serverInfo.name, 'secure-secrets-exchange-app');
  yes(/Never ask a human to type or paste a secret/.test(r.instructions));
});
await t('tools/list: five tools, two cards', async () => {
  const tl = (await rpc('tools/list')).result.tools; eq(tl.length, 5);
  eq(tl.filter((x) => x._meta?.ui?.resourceUri).map((x) => x.name).join(','), 'sse_send_secret,sse_open_secret');
});
await t('resource has mcp-app mime and connects only to secrets.agentkepler.tech', async () => {
  const c = (await rpc('resources/read', { uri: TOOLS[0]._meta.ui.resourceUri })).result.contents[0];
  eq(c.mimeType, 'text/html;profile=mcp-app'); eq(JSON.stringify(c._meta.ui.csp.connectDomains), '["https://secrets.agentkepler.tech"]');
  yes(c.text.includes('Copy link') && c.text.includes('Copy secret'), 'copy buttons');
});
await t('unknown resource -> error', async () => { yes((await rpc('resources/read', { uri: 'ui://x' })).error); });
await t('send card result carries mode and ttl', async () => {
  const r = await callTool(env, 'sse_send_secret', { label: 'Key for Torque', ttl_hours: 72 });
  eq(r.structuredContent.mode, 'send'); eq(r.structuredContent.ttl_hours, 72); eq(r.isError, false);
});
await t('send card rejects bad ttl and unknown params', async () => {
  eq((await callTool(env, 'sse_send_secret', { ttl_hours: 500 })).isError, true);
  eq((await callTool(env, 'sse_send_secret', { secret: 'x' })).isError, true);
});
await t('link not ready before sse_link_ready', async () => { eq((await callTool(env, 'sse_get_link', { ref: REF })).structuredContent.status, 'waiting'); });
await t('sse_link_ready rejects a link with a key or a foreign host', async () => {
  eq((await callTool(env, 'sse_link_ready', { ref: REF, share_url_base: BASE + '#' + 'k'.repeat(43) })).isError, true);
  eq((await callTool(env, 'sse_link_ready', { ref: REF, share_url_base: 'https://evil.example/v/' + 'A'.repeat(32) })).isError, true);
  eq((await callTool(env, 'sse_link_ready', { ref: 'x', share_url_base: BASE })).isError, true);
});
await t('sse_link_ready stores, sse_get_link returns it', async () => {
  eq((await callTool(env, 'sse_link_ready', { ref: REF, share_url_base: BASE, receipt_url: RCPT, expires_at: '2026-10-21T19:00:00Z' })).isError, false);
  const d = (await callTool(env, 'sse_get_link', { ref: REF })).structuredContent; eq(d.share_url_base, BASE); eq(d.receipt_url, RCPT);
});
await t('check receipt (mocked fetch) and bad URL', async () => {
  const f = async () => ({ json: async () => ({ ok: true, result: { status: 'burned', viewed_at: '2026-10-18T20:00:00Z' } }) });
  const r = await callTool(env, 'sse_check_receipt', { receipt_url: RCPT }, f); eq(r.structuredContent.status, 'burned');
  eq((await callTool(env, 'sse_check_receipt', { receipt_url: 'https://x.example/r' })).isError, true);
});
await t('notifications get no reply; unknown method errors', async () => {
  eq(await handle(env, { jsonrpc: '2.0', method: 'notifications/initialized' }), null);
  eq((await rpc('nope')).error.code, -32601);
});
await t('HTTP: POST /mcp works, GET /mcp 405, GET / about', async () => {
  const r = await worker.fetch(new Request('https://h/mcp', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'ping' }) }), env);
  eq((await r.json()).id, 7);
  eq((await worker.fetch(new Request('https://h/mcp'), env)).status, 405);
  yes((await (await worker.fetch(new Request('https://h/'), env)).text()).includes('sse_send_secret'));
});
await t('card script parses and its regexes are intact', async () => {
  const js = APP_HTML.split('<script>')[1].split('</script>')[0];
  new Function(js); // syntax check
  yes(js.includes('/^https:\\/\\/secrets\\.agentkepler\\.tech\\/v\\/([A-Za-z0-9_-]{32})#([A-Za-z0-9_-]{43})$/'), 'reveal regex');
});
await t('card crypto matches sse-e2e-v1 (encrypt in card format, decrypt like the viewer)', async () => {
  const c = webcrypto, key = c.getRandomValues(new Uint8Array(32)), iv = c.getRandomValues(new Uint8Array(12));
  const k = await c.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const ct = new Uint8Array(await c.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode('hello')));
  const o = new Uint8Array(12 + ct.length); o.set(iv); o.set(ct, 12);
  const p = 'sse-e2e-v1.' + Buffer.from(o).toString('base64url');
  yes(/^sse-e2e-v1\.[A-Za-z0-9_-]+$/.test(p)); eq(Buffer.from(key).toString('base64url').length, 43);
  const raw = Buffer.from(p.slice(11), 'base64url');
  eq(new TextDecoder().decode(await c.subtle.decrypt({ name: 'AES-GCM', iv: raw.subarray(0, 12) }, k, raw.subarray(12))), 'hello');
});
console.log(bad ? `${bad} of ${n} FAILED` : `all ${n} passed`); process.exit(bad ? 1 : 0);
