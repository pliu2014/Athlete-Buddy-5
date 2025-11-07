#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FRONTEND_DIR="$ROOT/frontend"
BACKEND_DIR="$ROOT/backend"

# Stop previous (best-effort)
for f in "$ROOT/frontend.dev.pid" "$ROOT/backend.dev.pid"; do
  if [ -f "$f" ]; then
    pid="$(cat "$f" 2>/dev/null || true)"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
    rm -f "$f"
  fi
done

# Frontend
cd "$FRONTEND_DIR"
if [ ! -d node_modules ]; then
  npm install
fi
nohup npm run dev >"$ROOT/frontend.dev.log" 2>&1 & echo $! > "$ROOT/frontend.dev.pid"

# Backend
cd "$BACKEND_DIR"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install -r requirements.txt

if [ ! -f .env ]; then
  cat > .env <<'ENV'
SECRET_KEY=change-me
COOKIE_SECURE=false
FRONTEND_ORIGIN=http://127.0.0.1:5173
# Optional: Google Sign-In
# GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
# Optional: Strava
# STRAVA_CLIENT_ID=
# STRAVA_CLIENT_SECRET=
# STRAVA_REDIRECT_URI=http://127.0.0.1:5050/api/auth/strava/callback
ENV
fi

nohup python app.py >"$ROOT/backend.dev.log" 2>&1 & echo $! > "$ROOT/backend.dev.pid"

echo "Frontend: http://127.0.0.1:5173"
echo "Backend:  http://127.0.0.1:5050/api"
echo "Logs:     $ROOT/frontend.dev.log, $ROOT/backend.dev.log"
