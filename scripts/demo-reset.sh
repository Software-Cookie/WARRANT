#!/usr/bin/env bash
# Restores the demo data to its initial state in about a second. Warrant's own configuration (tools, agent, policy)
# is applied once by demo-up.sh; the audit chain is append-only by design and is never reset. Escalations parked by
# an earlier run stay parked until their timer denies them; each run works on the escalation it created.
source "$(dirname "$0")/lib.sh"
start=$(date +%s%N)
"${COMPOSE[@]}" exec -T postgres psql -q -U postgres -d acme -v ON_ERROR_STOP=1 -c "SELECT * FROM acme_reset();"
log "demo data reset in $(( ($(date +%s%N) - start) / 1000000 )) ms"
