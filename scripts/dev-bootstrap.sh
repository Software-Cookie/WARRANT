#!/usr/bin/env bash
# Generates local-only secrets into .local/ (git-ignored). Nothing here is ever committed or reused in Google Cloud,
# where target credentials live in Secret Manager and signing keys in Cloud KMS.
source "$(dirname "$0")/lib.sh"
mkdir -p "$ROOT/.local/secrets"
# The directory stays owner-only, so other host users cannot reach the token.
chmod 700 "$ROOT/.local" "$ROOT/.local/secrets" 2>/dev/null || true
token="$ROOT/.local/secrets/acme-erp-token"
if [[ ! -s "$token" ]]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$token"
  log "generated the demo ERP service token (.local/secrets/acme-erp-token)"
else
  log "demo ERP service token already present"
fi
# The file itself must be world-readable: it is bind-mounted into containers that run as uid 10001, not the host
# user. On Linux a 600 file is unreadable there (Docker Desktop on Windows/macOS hides this). The 700 directory above
# still keeps it from other host users.
chmod 644 "$token" 2>/dev/null || true
