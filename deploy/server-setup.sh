#!/usr/bin/env bash
# Secure Secrets Exchange - runs ON the VPS as root, from /opt/sse. Safe to re-run.
# 1 Docker  2 secrets (generated here, never printed)  3 core + Valkey  4 service API token
# 5 gateway  6 local smoke tests  7 Cloudflare Tunnel for secrets.agentkepler.tech  8 public checks
set -euo pipefail
cd /opt/sse
HOSTNAME_PUBLIC=secrets.agentkepler.tech
TUNNEL=secure-secrets-exchange
log(){ printf '\n== %s\n' "$*"; }
envget(){ grep -E "^$1=" "$2" 2>/dev/null | head -1 | cut -d= -f2-; }

log "1. Docker"
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2 >/dev/null
  systemctl enable --now docker >/dev/null
fi
docker --version; docker compose version

log "2. Secrets (generated on this server; values are never printed)"
umask 077
[ -f .env ] || echo "VALKEY_PASSWORD=$(openssl rand -hex 32)" > .env
if [ ! -f core.env ]; then cat > core.env <<EOF
SECRET=$(openssl rand -hex 32)
HOST=$HOSTNAME_PUBLIC
SSL=true
AUTH_SIGNUP=false
BRAND_PRODUCT_NAME=Secure Secrets Exchange
BRAND_PRIMARY_COLOR=#0E6B62
UI_ENABLED=false
PRICING_URL=
FOOTER_VERSION_ENABLED=false
TERMS_URL=
PRIVACY_URL=
INCOMING_ENABLED=false
TTL_OPTIONS=300 3600 86400 604800
EOF
fi
if [ ! -f gateway.env ]; then cat > gateway.env <<EOF
PUBLIC_ORIGIN=https://$HOSTNAME_PUBLIC
SERVICE_PATH=$(openssl rand -hex 20)
QATOM_FULFILMENT_TOKEN=$(openssl rand -hex 24)
INBOX_TOKEN=$(openssl rand -hex 24)
GATEWAY_KEY=$(openssl rand -hex 32)
CORE_API_USER=
CORE_API_TOKEN=
ITEM_ID_CREATE=
ITEM_ID_REQUEST=
ITEM_ID_RETRIEVE=
ITEM_ID_FEEDBACK=
EOF
fi
chmod 600 .env core.env gateway.env
echo "secret files present: .env core.env gateway.env (mode 600)"

log "3. Secrets core + Valkey"
docker compose pull -q app maindb
docker compose up -d app maindb
printf 'waiting for the core'
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOSTNAME_PUBLIC" -H 'X-Forwarded-Proto: https' http://127.0.0.1:3000/api/v2/status || true)
  [ "$code" = 200 ] && break; printf '.'; sleep 5
done; echo " status $code"
[ "$code" = 200 ] || { docker compose logs --tail 60 app; echo "STOP: the core did not come up."; exit 1; }

log "4. Service account and API token for the gateway"
USER_EMAIL="gateway@$HOSTNAME_PUBLIC"
if [ -z "$(envget CORE_API_TOKEN gateway.env)" ]; then
  OUT=$(docker compose exec -T app bin/ots apitoken "$USER_EMAIL" --create 2>&1 || true)
  TOKEN=$(printf '%s\n' "$OUT" | sed -n 's/.*API Token: *\([A-Za-z0-9]*\).*/\1/p' | head -1)
  [ -n "$TOKEN" ] || { printf '%s\n' "$OUT" | grep -v -i token | tail -20; echo "STOP: could not create the API token."; exit 1; }
  sed -i "s|^CORE_API_USER=.*|CORE_API_USER=$USER_EMAIL|; s|^CORE_API_TOKEN=.*|CORE_API_TOKEN=$TOKEN|" gateway.env
  echo "API token created for $USER_EMAIL (stored in gateway.env)"
else echo "API token already set"; fi

log "5. Gateway"
docker compose up -d --build gateway
for i in $(seq 1 30); do [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/status)" = 200 ] && break; sleep 2; done
curl -s http://127.0.0.1:8080/status | head -c 200; echo

log "6. Local smoke tests"
SP=$(envget SERVICE_PATH gateway.env); TK=$(envget QATOM_FULFILMENT_TOKEN gateway.env)
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
echo "create without header: $(code -X POST http://127.0.0.1:8080/paid/$SP/create -H 'content-type: application/json' -d '{"payload":"x"}')  (want 404)"
R=$(curl -s -X POST "http://127.0.0.1:8080/paid/$SP/create" -H "authorization: Bearer $TK" -H 'content-type: application/json' -d '{"payload":"deploy smoke test","ttl_hours":1}')
if printf '%s' "$R" | grep -q '"share_url"'; then echo "create with header: ok (share link made)"
else
  echo "create with header failed; core said: $(printf '%s' "$R" | head -c 300)"
  echo "Retrying with an admin-role service account (the core may require the api_access entitlement)."
  docker compose exec -T app bin/ots customers create "admin-$USER_EMAIL" --role colonel >/dev/null 2>&1 || true
  OUT=$(docker compose exec -T app bin/ots apitoken "admin-$USER_EMAIL" 2>&1 || true)
  TOKEN=$(printf '%s\n' "$OUT" | sed -n 's/.*API Token: *\([A-Za-z0-9]*\).*/\1/p' | head -1)
  [ -n "$TOKEN" ] && sed -i "s|^CORE_API_USER=.*|CORE_API_USER=admin-$USER_EMAIL|; s|^CORE_API_TOKEN=.*|CORE_API_TOKEN=$TOKEN|" gateway.env
  docker compose up -d --force-recreate gateway; sleep 5
  R=$(curl -s -X POST "http://127.0.0.1:8080/paid/$SP/create" -H "authorization: Bearer $TK" -H 'content-type: application/json' -d '{"payload":"deploy smoke test","ttl_hours":1}')
  printf '%s' "$R" | grep -q '"share_url"' && echo "create with header: ok after retry" || { echo "STOP: create still failing: $(printf '%s' "$R" | head -c 300)"; docker compose logs --tail 40 app; exit 1; }
fi
R=$(curl -s -X POST "http://127.0.0.1:8080/paid/$SP/request" -H "authorization: Bearer $TK" -H 'content-type: application/json' -d '{"ttl_hours":1,"label":"deploy smoke test"}')
H=$(printf '%s' "$R" | sed -n 's/.*"request_handle": *"\(REQ-[A-Za-z0-9_-]*\)".*/\1/p' | head -1)
echo "request: $([ -n "$H" ] && echo ok || echo FAILED)"
echo "retrieve (free): $(curl -s -X POST http://127.0.0.1:8080/api/retrieve -H 'content-type: application/json' -d "{\"request_handle\":\"$H\"}" | grep -o '"status": *"[a-z]*"' | head -1)  (want waiting)"

log "7. Cloudflare Tunnel for $HOSTNAME_PUBLIC"
if ! command -v cloudflared >/dev/null; then echo "STOP: cloudflared is not installed"; exit 1; fi
if [ ! -f /root/.cloudflared/cert.pem ]; then
  echo ">>> Open the link cloudflared prints below, sign in to Cloudflare, and choose the agentkepler.tech zone. <<<"
  cloudflared tunnel login
fi
if ! cloudflared tunnel list 2>/dev/null | awk '{print $2}' | grep -qx "$TUNNEL"; then cloudflared tunnel create "$TUNNEL"; fi
TID=$(cloudflared tunnel list 2>/dev/null | awk -v n="$TUNNEL" '$2==n{print $1}' | head -1)
[ -n "$TID" ] || { echo "STOP: tunnel id not found"; exit 1; }
cloudflared tunnel route dns "$TUNNEL" "$HOSTNAME_PUBLIC" 2>&1 | tail -1 || true
mkdir -p /etc/cloudflared
cp "/root/.cloudflared/$TID.json" /etc/cloudflared/ 2>/dev/null || true
cat > /etc/cloudflared/config.yml <<EOF
tunnel: $TID
credentials-file: /etc/cloudflared/$TID.json
ingress:
  - hostname: $HOSTNAME_PUBLIC
    path: ^/(|status|security|llms\.txt|\.well-known/security\.txt|paid/[^/]+/(create|request)|in/[A-Za-z0-9_-]+|v/[A-Za-z0-9_-]+|api/(retrieve|feedback|inbox|e2e/(reveal|receipt)/[A-Za-z0-9_-]+))$
    service: http://127.0.0.1:8080
  - hostname: $HOSTNAME_PUBLIC
    path: ^/((secret|receipt|private)/[a-z0-9]{20,}|api/v3/guest/(secret|receipt)/[a-z0-9]{20,}(/(reveal|burn))?|dist/.+|favicon\.ico|robots\.txt|img/.+)$
    service: http://127.0.0.1:3000
  - service: http_status:404
EOF
cloudflared tunnel --config /etc/cloudflared/config.yml ingress validate
if ! systemctl list-unit-files | grep -q '^cloudflared.service'; then cloudflared service install; fi
systemctl enable --now cloudflared >/dev/null 2>&1 || true
systemctl restart cloudflared; sleep 8; systemctl is-active cloudflared

log "8. Public checks"
sleep 5
echo "status:            $(code https://$HOSTNAME_PUBLIC/status)  (want 200)"
echo "llms.txt:          $(code https://$HOSTNAME_PUBLIC/llms.txt)  (want 200)"
echo "paid w/o header:   $(code -X POST https://$HOSTNAME_PUBLIC/paid/$SP/create -d '{}')  (want 404)"
echo "core secret page:  $(code https://$HOSTNAME_PUBLIC/secret/doesnotexist)  (want 200 or 404, not 5xx)"

log "9. Values for the Qatom seller dashboard (written to SECRET-catalog.md, mode 600)"
cat > SECRET-catalog.md <<EOF
# Secure Secrets Exchange - Qatom catalog values (SECRET: never share, never paste into chat)

| Item | Price | Method | Endpoint | Request header (Sensitive) |
|---|---|---|---|---|
| Secure Secrets Exchange: create | 0.100 | POST | https://$HOSTNAME_PUBLIC/paid/$SP/create | Authorization = Bearer $TK |
| Secure Secrets Exchange: request | 0.100 | POST | https://$HOSTNAME_PUBLIC/paid/$SP/request | Authorization = Bearer $TK |
| Secure Secrets Exchange: retrieve | 0 | POST | https://$HOSTNAME_PUBLIC/api/retrieve | none |
| Secure Secrets Exchange: feedback | 0 | POST | https://$HOSTNAME_PUBLIC/api/feedback | none |

Feedback inbox (Kepler-only): curl -H "authorization: Bearer $(envget INBOX_TOKEN gateway.env)" https://$HOSTNAME_PUBLIC/api/inbox
EOF
chmod 600 SECRET-catalog.md
echo "DONE."
