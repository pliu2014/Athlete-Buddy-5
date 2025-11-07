#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

stop_one() {
  local pidfile="$1"
  if [ -f "$pidfile" ]; then
    local pid
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 0.5
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
}

stop_one "$ROOT/frontend.dev.pid"
stop_one "$ROOT/backend.dev.pid"
echo "Stopped dev servers."
