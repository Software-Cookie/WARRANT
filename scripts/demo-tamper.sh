#!/usr/bin/env bash
# Shows tamper evidence: a database superuser disables the append-only trigger and rewrites one audit row (turning a
# denial into an allow). The application role could not do this; an insider with superuser can, and the verifier
# then reports the break at that exact index. The row is restored afterwards so the demo can be repeated.
source "$(dirname "$0")/lib.sh"
export WARRANT_DEV_EMAIL="${WARRANT_DEV_EMAIL:-daniel@acme.example}" WARRANT_TENANT=acme
psql=("${COMPOSE[@]}" exec -T postgres psql -tA -U postgres -d warrant -v ON_ERROR_STOP=1)
idx=$("${psql[@]}" -c "SELECT idx FROM audit_entries WHERE tenant_id = 'acme' AND verdict = 'DENY' ORDER BY idx DESC LIMIT 1")
[[ -n "$idx" ]] || die "no denial in the chain yet; run ./scripts/demo-run.sh --gate on first"
log "rewriting audit entry $idx from DENY to ALLOW as a database superuser"
"${psql[@]}" -c "ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_no_update;
                 UPDATE audit_entries SET verdict = 'ALLOW' WHERE tenant_id = 'acme' AND idx = $idx;
                 ALTER TABLE audit_entries ENABLE TRIGGER audit_entries_no_update;" >/dev/null
report=$("$ROOT/scripts/warrant" audit verify --from 1 --to 99999 2>&1 || true)
echo "$report" | grep -E '"ok"|"broken_at"|"reason"|CHAIN BROKEN' || true
log "restoring entry $idx"
"${psql[@]}" -c "ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_no_update;
                 UPDATE audit_entries SET verdict = 'DENY' WHERE tenant_id = 'acme' AND idx = $idx;
                 ALTER TABLE audit_entries ENABLE TRIGGER audit_entries_no_update;" >/dev/null
echo "$report" | grep -q "CHAIN BROKEN at index $idx" || die "the verifier did not report the break at entry $idx"
log "tampering detected at entry $idx, as expected"
