# sse-e2e-v1: end-to-end format

The buyer's agent encrypts a secret before it reaches Secure Secrets Exchange. The key travels only in a link's fragment (the part after `#`), which browsers do not send to servers. The service, Qatom (the payment rail) and Cloudflare (TLS and tunnel) handle ciphertext only.

## Format

| Part | Value |
|---|---|
| Algorithm | AES-256-GCM, 16-byte tag, no associated data |
| Key | 32 random bytes, base64url without padding (43 characters) |
| IV | 12 random bytes, new for every encryption |
| Plaintext | UTF-8 |
| Payload | `sse-e2e-v1.` + base64url(IV + ciphertext + tag), without padding |
| Maximum payload | 14000 characters (a 10000-character secret fits) |

## Send a secret (create)

1. Make a key and encrypt the secret into a payload.
2. Buy **Secure Secrets Exchange: create** with `{"payload": "<payload>", "ttl_hours": 1-168}`. No passphrase: the key does that job.
3. The answer has `mode: "e2e"`, `share_url_base`, `receipt_url` and `expires_at`.
4. Give the recipient `share_url_base + "#" + key`.
5. The recipient's browser shows a **Reveal** button. On click it fetches the ciphertext once (`POST /api/e2e/reveal/<id>`, which deletes it on the server), then decrypts locally with WebCrypto. Link previews don't burn it, because nothing is fetched until the click.
6. `GET receipt_url` returns `waiting`, `viewed`, `burned` or `expired`. `POST {"action":"burn"}` to it deletes the secret early. Both are free.

## Collect a secret (request)

1. Make a key. Buy **Secure Secrets Exchange: request** as usual.
2. Give the sender `request_url + "#" + key`. The page shows "End-to-end encrypted", and the sender's browser encrypts the secret (and the optional note) before submitting.
3. Poll the free retrieve URL with `request_handle`. When delivered, `e2e` is `true` and `payload` (and `note`, if any) are sse-e2e-v1 payloads. Decrypt them with your key.

Without a `#key`, both flows fall back to standard mode.

## In-chat card (MCP App)

The send card in `mcp-app/` produces exactly this format in the card (WebCrypto), so links from the card, from agents and from the web pages are interchangeable. The open card accepts only a complete `https://secrets.agentkepler.tech/v/<32>#<43>` link and calls `POST /api/e2e/reveal/<id>` (CORS open, no credentials).

## Browser code is pinned

Each browser page runs a single inline script. Its SHA-256 is in the page's `Content-Security-Policy` header (`script-src 'sha256-...'`), so the browser runs no other script. `tools/verify.mjs` checks that the live hashes match this repository. The hashes are also listed at `/security` and in `/status`.

## Reference code

- `examples/e2e.py` (Python, `cryptography`)
- `examples/e2e.mjs` (Node 20+, no dependencies)

Each round-trips by itself, and each decrypts the other's output.
