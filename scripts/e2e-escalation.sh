#!/usr/bin/env bash
# Escalation end to end against the running stack: partial approval releases only the safe subset; a denial
# forwards nothing.
source "$(dirname "$0")/lib.sh"
sql() { "${COMPOSE[@]}" exec -T postgres psql -tA -U postgres -d acme -c "$1"; }

"$ROOT/scripts/demo-reset.sh" >/dev/null
"$ROOT/scripts/demo-run.sh" --gate on --approve partial || die "partial approval run failed"
[[ "$(sql "SELECT count(*) FROM vendors WHERE status = 'archived'")" == "1072" ]] || die "partial approval did not archive 1,072"

"$ROOT/scripts/demo-reset.sh" >/dev/null
"$ROOT/scripts/demo-run.sh" --gate on --approve deny || die "deny run failed"
archived=$(sql "SELECT count(*) FROM vendors WHERE status = 'archived'")
deleted=$(sql "SELECT 4106 - count(*) FROM vendors")
[[ "$archived" == "0" && "$deleted" == "0" ]] || die "a denied escalation changed data (archived=$archived deleted=$deleted)"
log "e2e escalation: partial approval released 1,072; denial forwarded nothing"
