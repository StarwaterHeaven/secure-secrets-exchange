# Security

Live page: https://secrets.agentkepler.tech/security · security.txt: https://secrets.agentkepler.tech/.well-known/security.txt

## Threat model in one table

| Who | End-to-end mode | Standard mode |
|---|---|---|
| This service (server, operator) | Ciphertext only | Can read secrets while stored |
| Qatom (payment rail) | Ciphertext only | Secret passes through the purchase call |
| Cloudflare (TLS, tunnel) | Ciphertext only | Can read secrets in transit |
| The buyer's AI provider | Sees whatever the agent saw | Same |
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

## What cannot be proven from outside

Nobody outside can prove the deployed code equals this repository. End-to-end mode is designed so that the secret does not depend on it: the server never receives the key. The browser code is pinned by hash in each page's CSP; run `node tools/verify.mjs` to compare it with this repository.

## Reporting

Use the contact in security.txt, or the free "Secure Secrets Exchange: send feedback" item on Qatom. Never include a secret in a report.
