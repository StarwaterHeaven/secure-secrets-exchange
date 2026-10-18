// Secure Secrets Exchange: in-chat app (MCP App), as a Cloudflare Worker. No dependencies.
//
//   POST /mcp   MCP over Streamable HTTP (stateless JSON): initialize, tools/*, resources/*
//   GET  /      what this is
//
// Two cards render inside MCP Apps clients (Claude, ChatGPT, Hermes and others):
//   Send: the human types the secret INTO THE CARD. The card makes a key and encrypts (sse-e2e-v1, AES-256-GCM),
//         hands the model only the ciphertext, and the model buys "create" (Qatom catalog item 199) with it on the
//         Qatom master MCP. The model reports the link base with sse_link_ready; the card picks it up, adds its key
//         after # and shows the full link with a Copy button. The model never sees the secret or the key.
//   Open: the human pastes a link INTO THE CARD (not the chat). The card fetches the ciphertext once from
//         secrets.agentkepler.tech and decrypts it locally, with a Copy button.
// This app sells nothing and needs no sign-in; payments stay on Qatom. It is temporary: when Qatom serves MCP
// Apps itself, this second connection goes away.

const SSE = 'https://secrets.agentkepler.tech';
const UI_URI = 'ui://secure-secrets-exchange/card-v2'; // bump on every change to APP_HTML (hosts cache by URI)
const UI_MIME = 'text/html;profile=mcp-app';
const SERVER_INFO = { name: 'secure-secrets-exchange-app', title: 'Secure Secrets Exchange', version: '1.0.0' };
const VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const LINK_RE = /^https:\/\/secrets\.agentkepler\.tech\/v\/([A-Za-z0-9_-]{32})$/;
const RECEIPT_RE = /^https:\/\/secrets\.agentkepler\.tech\/api\/e2e\/receipt\/([A-Za-z0-9_-]{32})$/;
const REF_RE = /^[A-Za-z0-9_-]{16,40}$/;
const UI = { ui: { resourceUri: UI_URI } };

export const TOOLS = [
  {
    name: 'sse_send_secret',
    title: 'Send a secret (in-chat card)',
    description: 'Open a card where the human types a secret to send as a one-time link. Never ask the human to type the secret in the chat. The card encrypts it and then sends you the ciphertext and a ref: buy "Secure Secrets Exchange: create" (Qatom catalog item 199, 0.10 USD-TDN) on the Qatom master MCP with that ciphertext as payload, then call sse_link_ready with the ref and the share_url_base, receipt_url and expires_at from the receipt. The card adds the key and shows the full link; you never see the secret or the key.',
    inputSchema: { type: 'object', properties: {
      label: { type: 'string', maxLength: 80, description: 'Optional. What is being sent, shown on the card (e.g. "Staging API key for Torque").' },
      ttl_hours: { type: 'integer', minimum: 1, maximum: 168, description: 'Optional. Hours until an unopened link expires, 1 to 168. Default 24.' },
    }, additionalProperties: false },
    _meta: UI,
  },
  {
    name: 'sse_link_ready',
    title: 'Hand the paid link to the card',
    description: 'After buying item 199 for a send card, pass the ref the card gave you and share_url_base, receipt_url and expires_at from the Qatom receipt. The card then shows the complete link with its key. Free.',
    inputSchema: { type: 'object', required: ['ref', 'share_url_base'], properties: {
      ref: { type: 'string', description: 'The ref the card gave you (16 to 40 letters, digits, - or _).' },
      share_url_base: { type: 'string', description: 'share_url_base from the receipt: https://secrets.agentkepler.tech/v/ followed by 32 characters.' },
      receipt_url: { type: 'string', description: 'receipt_url from the receipt.' },
      expires_at: { type: 'string', description: 'expires_at from the receipt.' },
    }, additionalProperties: false },
  },
  {
    name: 'sse_get_link',
    title: 'Card: fetch the paid link',
    description: 'Used by the send card to pick up what sse_link_ready stored. Returns the link base only (never a key). Free.',
    inputSchema: { type: 'object', required: ['ref'], properties: { ref: { type: 'string', description: 'The card ref.' } }, additionalProperties: false },
  },
  {
    name: 'sse_open_secret',
    title: 'Open a secret link (in-chat card)',
    description: 'Open a card where the human pastes a Secure Secrets Exchange link (with its #key) and reveals it. Tell the human to paste the link into the card, not into the chat. The secret is decrypted in the card and never reaches you. Free.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    _meta: UI,
  },
  {
    name: 'sse_check_receipt',
    title: 'Check whether a link was opened',
    description: 'Free. Given a receipt_url from a create purchase, says whether the link is waiting, viewed, burned or expired.',
    inputSchema: { type: 'object', required: ['receipt_url'], properties: { receipt_url: { type: 'string', description: 'receipt_url from the create receipt.' } }, additionalProperties: false },
  },
];

const ok = (id, result) => ({ jsonrpc: '2.0', id, result });
const rpcErr = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
const result = (text, data, isError = false) => ({ content: [{ type: 'text', text }], structuredContent: data, isError });

export async function callTool(env, name, args = {}, fetcher = fetch) {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) return null;
  const extra = Object.keys(args).filter((k) => !(k in tool.inputSchema.properties));
  if (extra.length) return result(`Not accepted: ${extra.join(', ')}.`, { ok: false, error: 'unknown_parameter' }, true);
  switch (name) {
    case 'sse_send_secret': {
      const ttl = args.ttl_hours === undefined ? 24 : Number(args.ttl_hours);
      if (!Number.isInteger(ttl) || ttl < 1 || ttl > 168) return result('ttl_hours must be 1 to 168.', { ok: false, error: 'bad_value' }, true);
      const label = String(args.label || '').slice(0, 80);
      return result('The send card is open. Ask the human to type the secret into the card (never into the chat) and press Encrypt. The card will then message you a ref and a ciphertext to buy item 199 with.',
        { ok: true, mode: 'send', label, ttl_hours: ttl });
    }
    case 'sse_open_secret':
      return result('The open card is showing. Ask the human to paste the complete link into the card (not into the chat) and press Reveal. You will be told when it was revealed, never what it said.', { ok: true, mode: 'open' });
    case 'sse_link_ready': {
      if (!REF_RE.test(String(args.ref || ''))) return result('ref is not a card ref.', { ok: false, error: 'bad_value' }, true);
      if (!LINK_RE.test(String(args.share_url_base || ''))) return result('share_url_base must be https://secrets.agentkepler.tech/v/ followed by 32 characters, as in the create receipt (without any #).', { ok: false, error: 'bad_value' }, true);
      if (args.receipt_url && !RECEIPT_RE.test(String(args.receipt_url))) return result('receipt_url is not a Secure Secrets Exchange receipt URL.', { ok: false, error: 'bad_value' }, true);
      const rec = { share_url_base: args.share_url_base, receipt_url: args.receipt_url || null, expires_at: String(args.expires_at || '').slice(0, 40) || null, at: new Date().toISOString() };
      await env.LINKS.put('ref:' + args.ref, JSON.stringify(rec), { expirationTtl: 7200 });
      return result('Done. The card now shows the complete link with a Copy button. Do not ask for the key: it stays in the card.', { ok: true, ...rec });
    }
    case 'sse_get_link': {
      if (!REF_RE.test(String(args.ref || ''))) return result('bad ref', { ok: false, error: 'bad_value' }, true);
      const raw = await env.LINKS.get('ref:' + args.ref);
      return raw ? result('Link base ready.', { ok: true, ...JSON.parse(raw) }) : result('Not ready yet.', { ok: false, status: 'waiting' });
    }
    case 'sse_check_receipt': {
      if (!RECEIPT_RE.test(String(args.receipt_url || ''))) return result('receipt_url must be a Secure Secrets Exchange receipt URL.', { ok: false, error: 'bad_value' }, true);
      try {
        const r = await fetcher(args.receipt_url, { headers: { accept: 'application/json' } });
        const j = await r.json();
        const st = j?.result?.status || 'unknown';
        return result(`Link status: ${st}.${j?.result?.viewed_at ? ' Opened at ' + j.result.viewed_at + '.' : ''}`, { ok: true, status: st, viewed_at: j?.result?.viewed_at || null, expires_at: j?.result?.expires_at || null });
      } catch { return result('The receipt could not be read just now. Try again in a minute.', { ok: false, status: 'unavailable' }); }
    }
  }
}

export async function handle(env, m, fetcher) {
  if (!m || m.jsonrpc !== '2.0' || !m.method) return m && m.id != null ? rpcErr(m.id, -32600, 'invalid request') : null;
  if (m.id === undefined || m.id === null) return null;
  const p = m.params || {};
  switch (m.method) {
    case 'initialize':
      return ok(m.id, {
        protocolVersion: VERSIONS.includes(p.protocolVersion) ? p.protocolVersion : VERSIONS[0],
        capabilities: { tools: { listChanged: false }, resources: { listChanged: false }, extensions: { 'io.modelcontextprotocol/ui': { mimeTypes: [UI_MIME] } } },
        serverInfo: SERVER_INFO,
        instructions: 'Secure Secrets Exchange in-chat cards. Never ask a human to type or paste a secret, a key or a #link into the chat: open sse_send_secret or sse_open_secret and let them use the card. Paid items (create 199, request 198) are bought on the Qatom master MCP (https://mcp.m.todaq.net). Details: https://secrets.agentkepler.tech/llms.txt',
      });
    case 'ping': return ok(m.id, {});
    case 'tools/list': return ok(m.id, { tools: TOOLS });
    case 'tools/call': {
      const r = await callTool(env, p.name, p.arguments || {}, fetcher);
      return r ? ok(m.id, r) : rpcErr(m.id, -32602, `unknown tool ${p.name}`);
    }
    case 'resources/list': return ok(m.id, { resources: [{ uri: UI_URI, name: 'Secure Secrets Exchange card', mimeType: UI_MIME }] });
    case 'resources/templates/list': return ok(m.id, { resourceTemplates: [] });
    case 'resources/read':
      if (p.uri !== UI_URI) return rpcErr(m.id, -32002, 'resource not found');
      return ok(m.id, { contents: [{ uri: UI_URI, mimeType: UI_MIME, text: APP_HTML, _meta: { ui: { prefersBorder: true, csp: { connectDomains: [SSE], resourceDomains: [] } } } }] });
    case 'prompts/list': return ok(m.id, { prompts: [] });
    default: return rpcErr(m.id, -32601, `method not found: ${m.method}`);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/mcp') {
      if (request.method === 'DELETE') return new Response(null, { status: 204 });
      if (request.method !== 'POST') return new Response('MCP server. POST JSON-RPC here.', { status: 405, headers: { allow: 'POST' } });
      let body; try { body = await request.json(); } catch { return Response.json(rpcErr(null, -32700, 'parse error'), { status: 400 }); }
      const batch = Array.isArray(body);
      const out = (await Promise.all((batch ? body : [body]).map((m) => handle(env, m)))).filter(Boolean);
      if (!out.length) return new Response(null, { status: 202 });
      return Response.json(batch ? out : out[0], { headers: { 'cache-control': 'no-store' } });
    }
    if (url.pathname === '/' || url.pathname === '/llms.txt') return new Response(ABOUT, { headers: { 'content-type': 'text/plain; charset=utf-8' } });
    return new Response('not found', { status: 404 });
  },
};

const ABOUT = `Secure Secrets Exchange: in-chat app (MCP App)

Add ${'https://sse-mcp.agentkepler.tech/mcp'} as a custom connector in a client that supports MCP Apps (Claude, ChatGPT, Hermes). No sign-in.
Tools: sse_send_secret (send card), sse_open_secret (open card), sse_link_ready, sse_get_link, sse_check_receipt.
The secret and its key stay inside the card; the model sees ciphertext only. Payments are on the Qatom master MCP (https://mcp.m.todaq.net), item 199 create and 198 request.
Service, threat model and format: ${SSE}/security and ${SSE}/llms.txt . Source: https://github.com/StarwaterHeaven/secure-secrets-exchange (mcp-app/).
`;

// ---------- the card: self-contained HTML, speaks MCP Apps over postMessage; network only to secrets.agentkepler.tech ----------
export const APP_HTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{color-scheme:light dark;--bg:#fff;--fg:#0f1d1c;--mut:#4b5b59;--line:#d7e0df;--acc:#0e6b62;--ok:#1d7a4a;--warn:#8a5a00}
@media (prefers-color-scheme:dark){:root{--bg:#0f1514;--fg:#e8efee;--mut:#9fb0ae;--line:#2b3a39;--acc:#4fbfb2;--ok:#5cc28c;--warn:#e0b24a}}
*{box-sizing:border-box}body{margin:0;font:15px/1.45 system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--fg)}
.card{padding:16px;border:1px solid var(--line);border-radius:12px;max-width:560px}
h2{font-size:16px;margin:0 0 4px}.mut{color:var(--mut);font-size:13px}.lock{font-size:12px;color:var(--ok);margin:6px 0 10px}
textarea,input,select{width:100%;border:1px solid var(--line);border-radius:9px;padding:10px;font:13px/1.4 ui-monospace,Menlo,monospace;background:transparent;color:inherit}
textarea{min-height:96px}label{display:block;font-weight:600;font-size:13px;margin:10px 0 4px}
button{margin-top:10px;padding:9px 14px;border-radius:9px;border:0;background:var(--acc);color:#fff;font:600 14px system-ui,sans-serif;cursor:pointer}
button.sec{background:transparent;color:var(--acc);border:1px solid var(--line)}button[disabled]{opacity:.55;cursor:default}
.box{margin-top:10px;padding:10px;border:1px dashed var(--line);border-radius:9px;word-break:break-all;font:12px/1.4 ui-monospace,Menlo,monospace}
#st{margin-top:8px;font-size:13px;color:var(--mut)}.row{display:flex;gap:8px;flex-wrap:wrap}
</style></head><body><div class="card" id="root"><div class="mut">Secure Secrets Exchange - loading...</div></div>
<script>
var nextId=1,pending={},S={};
function send(m){window.parent.postMessage(m,'*')}
function request(method,params){var id=nextId++;send({jsonrpc:'2.0',id:id,method:method,params:params||{}});
  return new Promise(function(res,rej){pending[id]={res:res,rej:rej};setTimeout(function(){if(pending[id]){delete pending[id];rej(new Error(method+' timed out'))}},30000)})}
function notify(method,params){send({jsonrpc:'2.0',method:method,params:params||{}})}
function size(){notify('ui/notifications/size-changed',{height:document.documentElement.scrollHeight})}
function $(i){return document.getElementById(i)}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function tell(text){return request('ui/update-model-context',{content:[{type:'text',text:text}]}).catch(function(){})}
function bu(a){var s='';for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')}
function ub(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';var b=atob(s),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}
function copyText(t,btn,box){function done(){btn.textContent='Copied';setTimeout(function(){btn.textContent='Copy again'},2500)}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done,fallback)}else fallback();
  function fallback(){var r=document.createRange();r.selectNodeContents(box);var s=getSelection();s.removeAllRanges();s.addRange(r);
    var okc=false;try{okc=document.execCommand('copy')}catch(e){}btn.textContent=okc?'Copied':'Selected: press Ctrl/Cmd+C'}}
var LOCK='<div class="lock">&#128274; Stays in this card: the secret and its key never reach the chat, the AI or the server.</div>';
function sendCard(d){S.mode='send';S.ttl=d.ttl_hours||24;
  $('root').innerHTML='<h2>Send a secret'+(d.label?': '+esc(d.label):'')+'</h2>'+LOCK+
  '<label for="sec">Type or paste the secret here (not in the chat)</label><textarea id="sec" spellcheck="false" autocomplete="off"></textarea>'+
  '<div class="mut">One-time link, expires after '+S.ttl+' h if unopened. Encrypted here with AES-256-GCM before anything leaves.</div>'+
  '<button id="enc">Encrypt and send</button><div id="st" role="status"></div><div id="out"></div>';
  $('enc').onclick=encrypt;size()}
async function encrypt(){var t=$('sec').value;if(!t.trim()){$('st').textContent='Type the secret first.';return}
  if(!(window.crypto&&crypto.subtle)){$('st').textContent='This chat app cannot encrypt here (no WebCrypto). Use the web page instead.';return}
  $('enc').disabled=true;
  var key=crypto.getRandomValues(new Uint8Array(32)),iv=crypto.getRandomValues(new Uint8Array(12));
  var k=await crypto.subtle.importKey('raw',key,'AES-GCM',false,['encrypt']);
  var c=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:iv},k,new TextEncoder().encode(t)));
  var o=new Uint8Array(12+c.length);o.set(iv);o.set(c,12);
  S.key=bu(key);S.payload='sse-e2e-v1.'+bu(o);S.ref=bu(crypto.getRandomValues(new Uint8Array(18)));
  $('sec').value='';$('sec').hidden=true;document.querySelector('label[for=sec]').hidden=true;t=null;
  $('st').innerHTML='Encrypted. Only the ciphertext ('+S.payload.length+' characters) goes to the AI, which buys the link on Qatom (0.10 USD-TDN, you approve it). Waiting for the link...';
  var msg='Buy "Secure Secrets Exchange: create" (Qatom catalog item 199) with agent_checkout on the Qatom master MCP, arguments {"payload": "'+S.payload+'", "ttl_hours": '+S.ttl+'}. When it is delivered, call sse_link_ready with ref "'+S.ref+'" and the share_url_base, receipt_url and expires_at from the receipt. The secret and its key stay in my card; do not ask me for them.';
  request('ui/message',{role:'user',content:[{type:'text',text:msg}]}).catch(function(){
    $('out').innerHTML='<div class="mut">Your chat app did not take the message automatically. Copy this and send it in the chat (it holds only ciphertext):</div><div class="box" id="m"></div><button class="sec" id="cm">Copy message</button>';
    $('m').textContent=msg;$('cm').onclick=function(){copyText(msg,$('cm'),$('m'))};size()});
  size();poll(0)}
function poll(n){if(n>200){$('st').textContent='Still waiting. When the AI has bought the link, ask it to call sse_link_ready.';size();return}
  request('tools/call',{name:'sse_get_link',arguments:{ref:S.ref}}).then(function(r){var d=r&&r.structuredContent;
    if(d&&d.ok&&d.share_url_base)return showLink(d);setTimeout(function(){poll(n+1)},3000)}).catch(function(){setTimeout(function(){poll(n+1)},5000)})}
function showLink(d){var link=d.share_url_base+'#'+S.key;S.key=null;
  $('st').innerHTML='Link ready'+(d.expires_at?', expires '+esc(new Date(d.expires_at).toLocaleString()):'')+'. It opens once.';
  $('out').innerHTML='<div class="box" id="lk"></div><div class="row"><button id="cl">Copy link</button></div><div class="mut" style="margin-top:6px">Send it to the one person or agent it is for. The AI saw only the part before #.</div>';
  $('lk').textContent=link;$('cl').onclick=function(){copyText(link,$('cl'),$('lk'))};
  tell('The human now has the complete one-time link in the card (the key after # stayed in the card). Receipt: '+(d.receipt_url||'n/a')+'.');size()}
function openCard(){S.mode='open';
  $('root').innerHTML='<h2>Open a secret</h2>'+LOCK+'<label for="ln">Paste the complete link here (not in the chat)</label><input id="ln" spellcheck="false" autocomplete="off" placeholder="https://secrets.agentkepler.tech/v/...#...">'+
  '<button id="rv">Reveal</button><div id="st" role="status"></div><div id="out"></div>';$('rv').onclick=reveal;size()}
async function reveal(){var m=/^https:\\/\\/secrets\\.agentkepler\\.tech\\/v\\/([A-Za-z0-9_-]{32})#([A-Za-z0-9_-]{43})$/.exec($('ln').value.trim());
  if(!m){$('st').textContent='That is not a complete Secure Secrets Exchange link (it needs the part after #).';size();return}
  $('rv').disabled=true;$('ln').value='';$('st').textContent='Opening...';
  try{var r=await fetch('${SSE}/api/e2e/reveal/'+m[1],{method:'POST'}),j=await r.json();
    if(!r.ok||!j.ok){$('st').textContent=(j.error&&j.error.message)||'This secret is no longer available.';tell('The human tried to open a link; it was no longer available.');size();return}
    var ct=j.result.ciphertext,raw=ub(ct.slice(11)),k=await crypto.subtle.importKey('raw',ub(m[2]),'AES-GCM',false,['decrypt']);
    var pt=new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:raw.slice(0,12)},k,raw.slice(12)));
    $('st').textContent='Decrypted in this card. The server copy is now deleted: copy it now, it cannot be shown again.';
    $('out').innerHTML='<div class="box" id="sv"></div><div class="row"><button id="cs">Copy secret</button><button class="sec" id="cx">Clear from screen</button></div>';
    $('sv').textContent=pt;$('cs').onclick=function(){copyText(pt,$('cs'),$('sv'))};
    $('cx').onclick=function(){pt='';$('out').innerHTML='';$('st').textContent='Cleared.';size()};
    tell('The human revealed the secret in the card. Its contents were not shared with you.');
  }catch(e){$('st').textContent='Could not open or decrypt. The link may be incomplete or altered.'}
  size()}
window.addEventListener('message',function(e){var m=e.data;if(!m||m.jsonrpc!=='2.0')return;
  if(m.id!=null&&pending[m.id]&&!m.method){var p=pending[m.id];delete pending[m.id];m.error?p.rej(new Error(m.error.message)):p.res(m.result);return}
  if(m.method&&m.id!=null){send({jsonrpc:'2.0',id:m.id,result:{}});return}
  if(m.method==='ui/notifications/tool-result'){var d=m.params&&m.params.structuredContent;if(!d||S.mode)return;
    if(d.mode==='send')sendCard(d);else if(d.mode==='open')openCard()}});
request('ui/initialize',{appInfo:{name:'Secure Secrets Exchange',version:'1.0.0'},appCapabilities:{},protocolVersion:'2026-01-26'})
  .then(function(){notify('ui/notifications/initialized',{});size()}).catch(function(){});
</script></body></html>`;
