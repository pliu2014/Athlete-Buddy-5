# Athlete Buddy V5

React + MUI frontend with Flask backend. Secure cookies + CSRF; Firestore ready.

## Quick Start (2 terminals)

Terminal A – frontend (Vite):
```bash
cd frontend
npm install
npm run dev
# Local: http://127.0.0.1:5173
```

Terminal B – backend (Flask):
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cat > .env <<'ENV'
SECRET_KEY=change-me
COOKIE_SECURE=false
FRONTEND_ORIGIN=http://127.0.0.1:5173
# Optional: Google Sign-In (frontend reads VITE_GOOGLE_CLIENT_ID)
# GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
# Optional: Strava (see Integrations below)
# STRAVA_CLIENT_ID=
# STRAVA_CLIENT_SECRET=
# STRAVA_REDIRECT_URI=http://127.0.0.1:5050/api/auth/strava/callback
ENV
python app.py
# API base: http://127.0.0.1:5050/api
```

## Project structure

- `frontend/` – React + Vite + MUI
  - Global styles in `src/index.css`
  - Map tab implemented with React Leaflet (`src/components/MapView.tsx`)
- `backend/` – Flask app (`app.py`) with CORS, CSRF and Firestore usage helpers

## Environment variables (backend)

- `SECRET_KEY` – required for cookies/CSRF
- `COOKIE_SECURE` – `true` in prod (HTTPS), `false` in dev
- `FRONTEND_ORIGIN` – allowed origin for CORS (default `http://127.0.0.1:5173`)
- `GOOGLE_APPLICATION_CREDENTIALS` – JSON key path for Firestore (optional in dev)
- `STRAVA_CLIENT_ID`, `STRAVA_CLIENT_SECRET`, `STRAVA_REDIRECT_URI` – for Strava OAuth (optional)

## Preferences storage

- In production: Firestore collections `ab_prefs`, `ab_integrations`, etc.
- In local dev without Google ADC: automatic filesystem fallback at `backend/.devdata.json` so saving Preferences still works.

## Integrations – Strava (optional)

1) Create a Strava API app at `https://www.strava.com/settings/api`.
2) Set Redirect URI to `http://127.0.0.1:5050/api/auth/strava/callback`.
3) Add to `backend/.env`:
```bash
STRAVA_CLIENT_ID=your_id
STRAVA_CLIENT_SECRET=your_secret
STRAVA_REDIRECT_URI=http://127.0.0.1:5050/api/auth/strava/callback
```
4) Restart the backend. In the app: Settings → Integrations → Connect Strava.

Tokens are stored per user under Firestore `ab_integrations/{uid}.strava` when ADC is configured, or within the local dev store in dev mode.

## Troubleshooting

- Port busy (5050):
  ```bash
  lsof -ti tcp:5050 | xargs -r kill -9
  ```
- ADC/Firestore error when saving preferences: either set `GOOGLE_APPLICATION_CREDENTIALS` or rely on the dev fallback (`backend/.devdata.json`).
- Blue focus/tap highlight: customized in `frontend/src/index.css`.
- Map tiles not loading: ensure you’re online; we use OpenStreetMap default tiles by default.

## Useful scripts/commands

- Stop dev servers:
  ```bash
  # frontend
  kill $(cat frontend.dev.pid) 2>/dev/null || true
  # backend
  kill $(cat backend.dev.pid) 2>/dev/null || true
  ```

## Security notes

- CSRF: double submit cookie via `XSRF-TOKEN` + `X-XSRF-TOKEN` header (handled by frontend `apiFetch`).
- Cookies: `HttpOnly`, `SameSite=Lax`, `Secure` controlled by env.
