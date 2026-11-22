#!/usr/bin/env bash
# Generates local-only secrets into .local/ (git-ignored). Nothing here is ever committed or reused in Google Cloud,
# where target credentials live in Secret Manager and signing keys in Cloud KMS.
source "$(dirname "$0")/lib.sh"
mkdir -p "$ROOT/.local/secrets"
chmod 700 "$ROOT/.local" "$ROOT/.local/secrets" 2>/dev/null || true
token="$ROOT/.local/secrets/acme-erp-token"
if [[ ! -s "$token" ]]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$token"
  chmod 600 "$token" 2>/dev/null || true
  log "generated the demo ERP service token (.local/secrets/acme-erp-token)"
else
  log "demo ERP service token already present"
fi
