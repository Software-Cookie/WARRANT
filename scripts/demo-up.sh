#!/usr/bin/env bash
# Builds and starts the whole stack locally, then registers the demo tools, agent and policy.
source "$(dirname "$0")/lib.sh"
"$ROOT/scripts/dev-bootstrap.sh"
log "building and starting services (first build downloads dependencies; later runs are offline)"
"${COMPOSE[@]}" up -d --build --wait postgres redis classifier control-plane pep-gateway acme-erp
if [[ "${WARRANT_SKIP_CONSOLE:-0}" != "1" ]]; then
  "${COMPOSE[@]}" up -d --build --wait console
fi
"${COMPOSE[@]}" --profile demo build demo-agent
"${COMPOSE[@]}" --profile demo run --rm demo-agent setup
log "ready: gateway http://localhost:8080 · control plane http://localhost:8081 · console http://localhost:3000"
