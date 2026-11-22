#!/usr/bin/env bash
# Shared helpers for the local scripts. Sourced, not executed.
set -euo pipefail
# pwd -W gives a native path under Git Bash on Windows, which Docker needs; elsewhere it falls back to pwd.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && (pwd -W 2>/dev/null || pwd))"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")
export MSYS_NO_PATHCONV=1
log() { printf '\033[2m[warrant]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[warrant] %s\033[0m\n' "$*" >&2; exit 1; }
