#!/usr/bin/env bash
# ./scripts/demo-run.sh --gate off                 agent holds the ERP credential: deletes 1,284 vendors
# ./scripts/demo-run.sh --gate on [--approve partial|approve|deny|console]
source "$(dirname "$0")/lib.sh"
gate=""
extra=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --gate) gate="$2"; shift 2 ;;
    --approve) extra+=(--approve "$2"); shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done
[[ "$gate" == "on" || "$gate" == "off" ]] || die "usage: demo-run.sh --gate on|off [--approve partial|approve|deny|console]"
if [[ "$gate" == "off" ]]; then
  # Only in gate-off mode does the agent receive the target credential.
  "${COMPOSE[@]}" --profile demo run --rm \
    -v "$ROOT/.local/secrets/acme-erp-token:/run/secrets/acme-erp-token:ro" demo-agent run --gate off
else
  "${COMPOSE[@]}" --profile demo run --rm demo-agent run --gate on "${extra[@]}"
fi
