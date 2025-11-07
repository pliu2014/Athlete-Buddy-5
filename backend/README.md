# Athlete Buddy V5 – Backend (Flask)

## Setup

1. Create and activate venv

```bash
cd "Athlete Buddy V5/backend"
python3 -m venv .venv
source .venv/bin/activate
```

2. Install deps

```bash
pip install -r requirements.txt
```

3. Configure environment

Create a `.env` with:

```
SECRET_KEY=change-me
COOKIE_SECURE=false
FRONTEND_ORIGIN=http://127.0.0.1:5173
```

For Firestore, authenticate with ADC or set `GOOGLE_APPLICATION_CREDENTIALS`.

## Run (Dev)

```bash
python app.py
```

Exposes API at `http://127.0.0.1:5050/api/*`.

## Production

- Set env:
  - `ENVIRONMENT=production`
  - `FRONTEND_ORIGIN=https://your-frontend-domain`
  - `COOKIE_SECURE=true`
  - `SECRET_KEY` to a strong random value
  - `GOOGLE_CLIENT_ID` for Google Sign-In verification

- Run with Gunicorn:

```bash
gunicorn -w 2 -b 0.0.0.0:5050 'app:create_app()'
```

CORS is restricted to `FRONTEND_ORIGIN` in production, and security headers are applied. Use HTTPS end-to-end.
