#!/usr/bin/env bash
# Starts the full Warrant demo on this Google Compute Engine VM and publishes the console over HTTPS.
#   ./scripts/cloud-demo-up.sh --domain warrant.services   https://warrant.services (www redirects), automatic certificate
#   ./scripts/cloud-demo-up.sh                             https://<ip-with-dashes>.sslip.io (no domain needed)
#   ./scripts/cloud-demo-up.sh --http [--domain d]         plain HTTP, if certificate issuance fails
#   --access-code <code>   set the demo access code (6-64 letters, digits or dashes); default: a random 8-character code
#   --open                 no access code: anyone with the link can use the demo sign-in
# The domain and access-code choice are remembered, so later runs need no flags.
source "$(dirname "$0")/lib.sh"
mode="https"
domain=""
code_arg=""
open_demo=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --http) mode="http"; shift ;;
    --domain) domain="${2:-}"; shift 2 ;;
    --access-code) code_arg="${2:-}"; shift 2 ;;
    --open) open_demo="yes"; shift ;;
    *) die "unknown argument $1 (use --domain <name>, --http, --access-code <code>, --open)" ;;
  esac
done
mkdir -p "$ROOT/.local"
saved="$ROOT/.local/cloud-domain"
[[ -z "$domain" && -s "$saved" ]] && domain=$(cat "$saved")
if [[ -n "$domain" ]]; then
  domain=$(printf '%s' "$domain" | tr 'A-Z' 'a-z')
  [[ "$domain" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "not a valid domain name: $domain"
  printf '%s\n' "$domain" > "$saved"
fi

ip=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" || true)
[[ "$ip" =~ ^[0-9.]+$ ]] || die "could not read this VM's external IP (is this a Google Compute Engine VM with an external IP?)"

if [[ -n "$domain" ]]; then
  for name in "$domain" "www.$domain"; do
    resolved=$(getent ahostsv4 "$name" | awk '{print $1; exit}' || true)
    if [[ "$resolved" != "$ip" ]]; then
      log "WARNING: $name points to '${resolved:-nothing}', not this server ($ip)."
      log "         Fix the DNS A record (guide Part 4.5). HTTPS starts a few minutes after DNS is correct; no restart needed."
    else
      log "DNS ok: $name -> $ip"
    fi
  done
fi

if [[ "$mode" == "https" && -n "$domain" ]]; then
  site="$domain, www.$domain"; site_domain="$domain"; public="https://$domain"
elif [[ "$mode" == "https" ]]; then
  site="${ip//./-}.sslip.io"; site_domain="$site"; public="https://$site"
else
  site=":80"; site_domain="localhost.invalid"; public="http://${domain:-$ip}"
fi
# Second address for the control plane, used by a console hosted elsewhere (Vercel). HTTPS only.
if [[ "$mode" == "https" ]]; then
  api_host="api.$site_domain"; api_site="$api_host"; api_public="https://$api_host"
else
  api_site="http://api.localhost.invalid"; api_public=""
fi

"$ROOT/scripts/dev-bootstrap.sh"
code_file="$ROOT/.local/demo-access-code"
open_marker="$ROOT/.local/demo-open"
umask 077
if [[ -n "$code_arg" ]]; then
  [[ "$code_arg" =~ ^[A-Za-z0-9-]{6,64}$ ]] || die "access code must be 6-64 letters, digits or dashes"
  printf '%s
' "$code_arg" > "$code_file"
  rm -f "$open_marker"
elif [[ -n "$open_demo" ]]; then
  : > "$open_marker"
fi
if [[ -f "$open_marker" ]]; then
  code=""
else
  if [[ ! -s "$code_file" ]]; then
    head -c 512 /dev/urandom | tr -dc 'A-HJ-NP-Z2-9' | cut -c1-8 > "$code_file"
  fi
  code=$(tr -d '[:space:]' < "$code_file")
fi

key_file="$ROOT/.local/cp-proxy-key"
[[ -s "$key_file" ]] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' 
' > "$key_file"
api_key=$(tr -d '[:space:]' < "$key_file")

env_file="$ROOT/.local/cloud.env"
cat > "$env_file" <<ENV
WARRANT_SITE='$site'
WARRANT_DOMAIN='$site_domain'
WARRANT_PUBLIC_URL='$public'
WARRANT_DEMO_ACCESS_CODE='$code'
WARRANT_API_SITE='$api_site'
WARRANT_API_KEY='$api_key'
ENV

CLOUD=("${COMPOSE[@]}" -f "$ROOT/deploy/cloud-demo/compose.cloud.yml" --env-file "$env_file")
log "building and starting all services (first time: about 10-20 minutes)"
"${CLOUD[@]}" up -d --build --wait postgres redis classifier control-plane pep-gateway acme-erp console caddy
"${CLOUD[@]}" up -d --force-recreate caddy
"${COMPOSE[@]}" --profile demo build demo-agent
"${COMPOSE[@]}" --profile demo run --rm demo-agent setup
log "building the warrant command-line tool"
(cd "$ROOT" && ./gradlew -q :sdk-java:cliJar) || log "CLI build failed; the demo still works (retry: ./gradlew :sdk-java:cliJar)"

if [[ -n "$code" ]]; then
  access="$code   (saved in ~/WARRANT/.local/demo-access-code)"
else
  access="none - demo sign-in is open to anyone with the link"
fi
cat <<DONE
if [[ -n "$api_public" ]]; then
  cat <<API
   For a console on Vercel, set these in Vercel (Settings > Environment Variables):
     WARRANT_CONTROL_PLANE_URL = $api_public
     WARRANT_CP_PROXY_KEY      = $api_key   (saved in ~/WARRANT/.local/cp-proxy-key)
  ============================================================
API
fi

  ============================================================
   Warrant is live:   $public
   Access code:       $access
   Sign in as R. Menon (Approver) to run the demo.
   For judges, share the link and the access code.
  ============================================================
DONE
