#!/bin/bash
# Deploy the Secure Secrets Exchange in-chat app (Cloudflare Worker "sse-mcp" on sse-mcp.agentkepler.tech).
# Run from a Mac terminal in this folder:   bash deploy.sh
# No secrets: the app holds no keys and sells nothing. Result log: sse-mcp-deploy-result-<time>.txt
set -uo pipefail
cd "$(dirname "$0")"
TS=$(date +%Y%m%d-%H%M%S); LOG="sse-mcp-deploy-result-$TS.txt"
BASE="https://sse-mcp.agentkepler.tech"; WDEV="https://sse-mcp.hassan-khan-cd6.workers.dev"
exec > >(tee "$LOG") 2>&1
echo "== SSE in-chat app deploy $TS"
echo "== 1. npm install"; npm install --no-audit --no-fund || { echo "STOP: npm install failed"; exit 1; }
WR=./node_modules/.bin/wrangler
echo "== 2. tests"; node test/run.mjs || { echo "STOP: tests failed"; exit 1; }
echo "== 3. Cloudflare login"
if ! $WR whoami 2>&1 | grep -qi "logged in"; then $WR login || { echo "STOP: login failed"; exit 1; }; fi
echo "== 4. KV namespace for card refs"
if grep -q REPLACE_WITH_KV_ID wrangler.toml; then
  ID=$($WR kv namespace create sse-mcp-links 2>&1 | grep -oE '[0-9a-f]{32}' | head -1)
  if [ -z "$ID" ]; then
    ID=$($WR kv namespace list 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const a=JSON.parse(s);const n=a.find(x=>/sse-mcp-links$/.test(x.title));process.stdout.write(n?n.id:"")}catch{}})')
  fi
  [ -z "$ID" ] && { echo "STOP: could not create or find the KV namespace sse-mcp-links"; exit 1; }
  sed -i '' "s/REPLACE_WITH_KV_ID/$ID/" wrangler.toml 2>/dev/null || sed -i "s/REPLACE_WITH_KV_ID/$ID/" wrangler.toml
  echo "KV namespace ready ($ID)"
else echo "KV namespace already set in wrangler.toml"; fi
echo "== 5. Deploy"; $WR deploy || { echo "STOP: deploy failed"; exit 1; }
echo "== 6. Verify (waiting 20s for the custom domain)"; sleep 20
J='content-type: application/json'
for B in "$BASE"; do   # workers.dev stays off: the Worker answers only on its custom domain
  echo "-- $B"
  echo "about page:   $(curl -s -o /dev/null -w '%{http_code}' $B/)  (want 200)"
  echo "GET /mcp:     $(curl -s -o /dev/null -w '%{http_code}' $B/mcp)  (want 405)"
  echo "initialize:   $(curl -s -X POST -H "$J" -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' $B/mcp | grep -o '"io.modelcontextprotocol/ui"' | head -1)  (want \"io.modelcontextprotocol/ui\")"
  echo "tools:        $(curl -s -X POST -H "$J" -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' $B/mcp | grep -oE '"name":"sse_[a-z_]+"' | tr '\n' ' ')"
  echo "card:         $(curl -s -X POST -H "$J" -d '{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"ui://secure-secrets-exchange/card-v2"}}' $B/mcp | grep -oE 'text/html;profile=mcp-app' | head -1)  (want text/html;profile=mcp-app)"
done
echo "CORS on reveal (gateway): $(curl -s -o /dev/null -D - -X OPTIONS https://secrets.agentkepler.tech/api/e2e/reveal/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | grep -i '^access-control-allow-origin' | tr -d '\r')  (want access-control-allow-origin: *, after the gateway update)"
echo "== Done. Connector URL: $BASE/mcp"
