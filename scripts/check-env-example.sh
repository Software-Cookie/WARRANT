#!/usr/bin/env bash
# Fails if .env.example carries any value: it documents key names only.
set -euo pipefail
file="$(cd "$(dirname "$0")/.." && pwd)/.env.example"
bad=$(grep -nE '^[A-Z0-9_]+=.+' "$file" || true)
if [[ -n "$bad" ]]; then
  echo ".env.example must contain key names with empty values only:" >&2
  echo "$bad" >&2
  exit 1
fi
echo ".env.example: keys only"
