# Secure Secrets Exchange

One-time secret links for AI agents and the people they work with, sold per call on [Qatom](https://qatom.ai). Live at https://secrets.agentkepler.tech.

- **Create** (0.10 USD-TDN): send a secret as a link that shows it once, then deletes it.
- **Request** (0.10 USD-TDN): get a private link someone can use to send you a secret.
- **Retrieve** and **feedback**: free.

Recipients and senders need only a browser: no account, no payment.

**End-to-end mode** is the upgrade over the open-source secrets core underneath. Agents that can run code encrypt the secret themselves and put the key after `#` in the link. The service, Qatom and Cloudflare see ciphertext only. See [E2E-SPEC.md](E2E-SPEC.md) and [SECURITY.md](SECURITY.md). The reveal page has **Copy to clipboard** and **Clear from screen** buttons.

**In-chat app (MCP App).** For people whose AI app shows MCP Apps (Claude, ChatGPT, Hermes and others), add `https://sse-mcp.agentkepler.tech/mcp` as a second connector (no sign-in). The human types the secret into a card inside the chat, not into the chat itself. The card encrypts it end-to-end and gives the AI only the ciphertext to buy the link with on Qatom. The AI never sees the secret or the key. A second card opens links. Payments still go through the Qatom master MCP. This connector is temporary: it goes away when Qatom serves MCP Apps itself. See [mcp-app/README.md](mcp-app/README.md).

## What is in here

| Path | What |
|---|---|
| `gateway/server.mjs` | The Qatom gateway: paid tools, sender and viewer pages, end-to-end mode, security page, llms.txt |
| `gateway/test.mjs` | 39 tests, run with `node gateway/test.mjs` (in-memory store; set `REDIS_URL` to run them against Valkey) |
| `mcp-app/` | The in-chat app: a Cloudflare Worker serving two cards (send, open) over MCP. 14 tests: `node mcp-app/test/run.mjs` |
| `deploy/` | docker compose (secrets core, Valkey, gateway) and the server setup, including the Cloudflare Tunnel allowlist |
| `examples/` | sse-e2e-v1 in Python and Node |
| `tools/verify.mjs` | Checks that the live pages run exactly the browser code in this repository |

## Built on

The secrets core is the open-source project at https://github.com/onetimesecret/onetimesecret (MIT; licence in `licenses/`). It runs unmodified, at the version pinned in `deploy/docker-compose.yml`. This repository adds the gateway in front of it. No secrets or deployment credentials are included; `server-setup.sh` generates them on the server.

## Licence

MIT, see LICENSE.
