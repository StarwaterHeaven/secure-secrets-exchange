// Compare the browser scripts in this repository with what the live service pins in its pages' CSP.
// Usage: node tools/verify.mjs [https://secrets.agentkepler.tech]
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const origin = (process.argv[2] || 'https://secrets.agentkepler.tech').replace(/\/$/, '');
const src = readFileSync(new URL('../gateway/server.mjs', import.meta.url), 'utf8');
const pick = (name) => src.match(new RegExp(`const ${name} = String\\.raw\`([\\s\\S]*?)\`;`))[1];
const csp = (js) => `'sha256-${createHash('sha256').update(js, 'utf8').digest('base64')}'`;
const want = { viewer: csp(pick('VIEWER_JS')), sender: csp(pick('SENDER_JS')) };
const viewer = await fetch(`${origin}/v/${'a'.repeat(32)}`);
const status = await (await fetch(`${origin}/status`)).json();
const live = { viewer: viewer.headers.get('content-security-policy') || '', sender: status.result?.security?.sender_script_csp || '' };
let ok = true;
for (const k of ['viewer', 'sender']) {
  const match = live[k].includes(want[k]);
  ok &&= match;
  console.log(`${k} script: ${match ? 'MATCHES' : 'DIFFERS'} the source (${want[k]})`);
}
console.log('core version reported:', status.result?.security?.core_version);
process.exit(ok ? 0 : 1);
