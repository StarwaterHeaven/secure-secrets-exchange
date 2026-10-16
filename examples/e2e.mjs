// Secure Secrets Exchange end-to-end format (sse-e2e-v1), Node 20+ (built-in WebCrypto). No dependencies.
// Encrypt before you buy "create"; give the recipient share_url_base + "#" + key.
// For "request", give the sender request_url + "#" + key, then decrypt what retrieve returns.
const PREFIX = 'sse-e2e-v1.';
const { subtle } = globalThis.crypto;
const getRandomValues = (a) => globalThis.crypto.getRandomValues(a);
const b64u = (b) => Buffer.from(b).toString('base64url');
const ub64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));

export const newKey = () => b64u(getRandomValues(new Uint8Array(32)));

export async function encrypt(secret, key) {
  const iv = getRandomValues(new Uint8Array(12));
  const k = await subtle.importKey('raw', ub64u(key), 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(secret)));
  return PREFIX + b64u(Buffer.concat([iv, ct]));
}

export async function decrypt(payload, key) {
  if (!payload.startsWith(PREFIX)) throw new Error('not an sse-e2e-v1 payload');
  const raw = ub64u(payload.slice(PREFIX.length));
  const k = await subtle.importKey('raw', ub64u(key), 'AES-GCM', false, ['decrypt']);
  return new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, k, raw.slice(12)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const k = newKey();
  const p = await encrypt('sk-example-not-a-real-key', k);
  if ((await decrypt(p, k)) !== 'sk-example-not-a-real-key') throw new Error('round trip failed');
  console.log('payload for create:', p);
  console.log('append to share_url_base: #' + k);
}
