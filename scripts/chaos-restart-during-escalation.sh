#!/usr/bin/env bash
# Parks an escalation, restarts pep-gateway while it is pending, then approves: the release must still happen,
# because parked state lives in Postgres, not in gateway memory.
source "$(dirname "$0")/lib.sh"
export WARRANT_DEV_EMAIL=r.menon@acme.example WARRANT_TENANT=acme
"$ROOT/scripts/demo-reset.sh" >/dev/null
"$ROOT/scripts/demo-run.sh" --gate on --approve console > "$ROOT/.local/chaos-run.log" 2>&1 &
agent=$!
id=""
for _ in $(seq 1 60); do
  id=$("$ROOT/scripts/warrant" escalations list | grep -o '"id" : "esc_[A-Za-z0-9]*"' | grep -o 'esc_[A-Za-z0-9]*' | tail -1 || true)
  [[ -n "$id" ]] && break
  sleep 1
done
[[ -n "$id" ]] || die "no escalation was parked"
log "parked $id; restarting pep-gateway"
"${COMPOSE[@]}" restart pep-gateway
"${COMPOSE[@]}" up -d --wait pep-gateway
"$ROOT/scripts/warrant" escalations decide "$id" --action approve_partial >/dev/null
wait "$agent" || { cat "$ROOT/.local/chaos-run.log"; die "release did not complete after restart"; }
log "release survived a gateway restart"
