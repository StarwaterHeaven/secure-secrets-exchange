# Secure Secrets Exchange: in-chat app (MCP App)

A second, optional MCP connector that shows Secure Secrets Exchange as cards inside AI apps that support MCP Apps (Claude, ChatGPT, Hermes and others). It is temporary: when Qatom serves MCP Apps itself, the cards move there and this second connection goes away.

**Connector URL:** `https://sse-mcp.agentkepler.tech/mcp` (no sign-in). Payments stay on the Qatom master MCP (`https://mcp.m.todaq.net`).

## Why

Without it, a person who wants their AI to send a secret has to type the secret into the chat, so the AI provider sees it. With the cards, the person types it into the card, the card encrypts it (sse-e2e-v1), and the AI handles ciphertext only. The same goes for opening a link: paste it into the card, not the chat.

## Tools

| Tool | Card | What it does |
|---|---|---|
| `sse_send_secret` | Send | Opens the send card (optional `label`, `ttl_hours` 1-168). The human types the secret; the card encrypts it and messages the AI a ref and the ciphertext. |
| `sse_link_ready` | | The AI calls it after buying item 199 with that ciphertext: `ref`, `share_url_base`, `receipt_url`, `expires_at`. Kept 2 hours. |
| `sse_get_link` | | Used by the card to pick up the link base. It adds its key after `#` and shows the full link with **Copy link**. |
| `sse_open_secret` | Open | Opens the open card. The human pastes a link; the card fetches and decrypts it locally, with **Copy secret** and **Clear from screen**. |
| `sse_check_receipt` | | Free status of a link: waiting, viewed, burned or expired. |

## Flow (send)

1. Human: "Send Torque our webhook URL securely." The AI calls `sse_send_secret`.
2. The human types the secret into the card and presses **Encrypt and send**.
3. The card sends the AI: buy item 199 with `{"payload": "sse-e2e-v1....", "ttl_hours": 24}`, then call `sse_link_ready` with ref X. (If the app doesn't support `ui/message`, the card shows that text with a Copy button for the human to send.)
4. The AI buys on Qatom (0.10 USD-TDN; the human approves), then calls `sse_link_ready`.
5. The card shows the complete link with **Copy link**. The AI saw only the part before `#`.

## Run and deploy

```bash
node test/run.mjs     # 14 offline checks
bash deploy.sh        # Mac: tests, KV namespace, deploy, verify. No secrets.
```

Then add the connector in your AI app: Claude: Settings > Connectors > Add custom connector, URL above.

Hosts cache the card by URI: bump `UI_URI` (`card-v2` now) on every change to the card HTML.
