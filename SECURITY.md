# Security

Live page: https://secrets.agentkepler.tech/security · security.txt: https://secrets.agentkepler.tech/.well-known/security.txt

## Threat model in one table

| Who | End-to-end mode | Standard mode |
|---|---|---|
| This service (server, operator) | Ciphertext only | Can read secrets while stored |
| Qatom (payment rail) | Ciphertext only | Secret passes through the purchase call |
| Cloudflare (TLS, tunnel) | Ciphertext only | Can read secrets in transit |
| The buyer's AI provider | Sees whatever the agent saw (with the in-chat app: ciphertext only) | Same |
| Recipient | Once | Once |

End-to-end mode is the upgrade over the open-source secrets core this service is built on: with that core alone, the server encrypts with a key it holds. Here the buyer keeps the key, and the key never reaches any server.

## Storage and deletion

- **End-to-end links:** ciphertext in Valkey. Deleted atomically on first reveal (GETDEL), on burn, or on expiry (1 to 168 hours).
- **End-to-end requests:** the sender's browser encrypts. The gateway also seals the ciphertext with AES-256-GCM under its own key. Deleted on retrieval or expiry.
- **Standard links:** the open-source secrets core (pinned version, see `deploy/docker-compose.yml`), encrypted at rest with a server-held key. Deleted on first view or expiry.
- **Standard requests:** sealed by the gateway with AES-256-GCM under a server-held key. Deleted on retrieval or expiry.
- **Logs:** the gateway logs the tool name and Qatom's transaction id only. It never logs payloads, keys, handles or links.

## Exposure

The server sits behind a Cloudflare Tunnel; no ports are open to the internet. The tunnel sends only these paths to the secrets core: the secret and receipt pages, their two guest API calls (reveal and burn), and static assets. The core's own create APIs, sign-in and web app are not reachable. See the ingress rules in `deploy/server-setup.sh`.

Paid routes answer only Qatom's fulfilment call: a secret path plus a Sensitive `Authorization` header, compared in constant time. Anything else gets 404.

## In-chat app

`mcp-app/` is an optional second MCP connector (`https://sse-mcp.agentkepler.tech/mcp`) for AI apps that show MCP Apps. It closes the one gap in the table above: with it, the AI provider no longer sees the secret either.

- **Send card:** the human types the secret into a sandboxed card. The card makes the key and encrypts (sse-e2e-v1) in the card, then sends the AI only the ciphertext and a random ref. The AI buys create on Qatom with the ciphertext and reports the link base (no key) back to the app under that ref. The card adds its key after `#` and shows the full link with a Copy button. The ref and link base are kept up to 2 hours, then deleted; the app never receives a key, a secret or a full link.
- **Open card:** the human pastes the link into the card. The card fetches the ciphertext from `/api/e2e/reveal` and decrypts in the card. The card's CSP allows network access to this service only.
- The reveal and receipt API routes send `Access-Control-Allow-Origin: *` so the card can call them. They take no cookies or credentials, so this exposes nothing a direct request could not already get.
- Trust: the AI app runs the card. A malicious AI app could read what the human types into it, as it could read the chat. The card helps against the AI model, its logs and transcripts, and the transfer path, not against the app vendor.
- Temporary: when Qatom serves MCP Apps itself, the cards move there and this connector is retired.

## What cannot be proven from outside

Nobody outside can prove the deployed code equals this repository. End-to-end mode is designed so that the secret does not depend on it: the server never receives the key. The browser code is pinned by hash in each page's CSP; run `node tools/verify.mjs` to compare it with this repository. The in-chat card's HTML is served by the app (`resources/read`); compare it with `mcp-app/src/index.mjs`.

## Reporting

Use the contact in security.txt, or the free "Secure Secrets Exchange: send feedback" item on Qatom. Never include a secret in a report.
