#!/usr/bin/env bash
# Publish this folder as the public repo StarwaterHeaven/secure-secrets-exchange. Run on the Mac from this folder.
set -euo pipefail
cd "$(dirname "$0")"
REPO=StarwaterHeaven/secure-secrets-exchange
if [ -e SECRET-catalog.md ] || grep -rqE '2\.24\.201|[0-9a-f]{40}' --exclude=publish-repo.sh --exclude-dir=.git . ; then echo "STOP: something that looks like an infrastructure detail or secret is in the folder"; exit 1; fi
[ -d .git ] || git init -q -b main
git add -A
git -c user.name="${GIT_NAME:-StarwaterHeaven}" -c user.email="${GIT_EMAIL:-$(git config user.email || echo noreply@github.com)}" commit -q -m "Secure Secrets Exchange gateway: end-to-end mode (sse-e2e-v1), security page, pinned browser scripts

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01HSBG7YiH8CUxd6gmXf5anc" || echo "(nothing new to commit)"
if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
  if gh repo view "$REPO" >/dev/null 2>&1; then git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$REPO.git"; git push -u origin main
  else gh repo create "$REPO" --public --description "One-time secret links for AI agents on Qatom, with end-to-end mode" --source=. --push; fi
else
  echo "gh is not signed in. Create an empty public repo at https://github.com/new named secure-secrets-exchange under StarwaterHeaven, then run:"
  echo "  git remote add origin https://github.com/$REPO.git && git push -u origin main"
  exit 1
fi
echo "DONE: https://github.com/$REPO"
