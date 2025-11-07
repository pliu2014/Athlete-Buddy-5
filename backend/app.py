from __future__ import annotations

import os
from datetime import timedelta
from flask import Flask, jsonify, request, make_response, redirect
from flask_cors import CORS
from itsdangerous import URLSafeSerializer
from dotenv import load_dotenv
import requests
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

load_dotenv()


def create_app() -> Flask:
    app = Flask(__name__)

    environment = os.environ.get("ENVIRONMENT", os.environ.get("FLASK_ENV", "development")).lower()
    is_production = environment in ("prod", "production")

    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32)),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(os.environ.get("COOKIE_SECURE", "true" if is_production else "false").lower() == "true"),
        PERMANENT_SESSION_LIFETIME=timedelta(days=14),
        JSON_SORT_KEYS=False,
    )

    # CORS with credentials: in production allow only explicit origin(s)
    allowed_origin = os.environ.get("FRONTEND_ORIGIN", "http://127.0.0.1:5173")
    cors_origins = [allowed_origin]
    if not is_production:
        cors_origins += [r"http://127\.0\.0\.1:\d+", r"http://localhost:\d+"]
    CORS(app, resources={r"/api/*": {"origins": cors_origins}}, supports_credentials=True, expose_headers=["XSRF-TOKEN"])

    xsrf_cookie_name = "XSRF-TOKEN"

    @app.after_request
    def set_csrf_cookie(response):
        # Issue a lightweight signed token per response to enable double-submit CSRF
        signer = URLSafeSerializer(app.config["SECRET_KEY"], salt="xsrf")
        token = signer.dumps({"t": "ok"})
        response.set_cookie(
            xsrf_cookie_name,
            token,
            max_age=60 * 60,  # 1 hour
            httponly=False,  # must be readable by frontend
            samesite="Lax",
            secure=app.config["SESSION_COOKIE_SECURE"],
        )
        # Security headers (lightweight, CSP omitted to avoid dev breakage)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
        if is_production and app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        return response

    def verify_csrf():
        signer = URLSafeSerializer(app.config["SECRET_KEY"], salt="xsrf")
        header_token = request.headers.get("X-XSRF-TOKEN")
        cookie_token = request.cookies.get(xsrf_cookie_name)
        if not header_token or not cookie_token:
            return False
        try:
            # ensure header token matches cookie token and is valid
            if header_token != cookie_token:
                return False
            signer.loads(cookie_token)
            return True
        except Exception:
            return False

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"})

    @app.route("/api/session", methods=["POST"])
    def create_session():
        if not verify_csrf():
            return jsonify({"error": "CSRF validation failed"}), 403
        resp = make_response(jsonify({"message": "session created"}))
        # Example cookie demonstrating secure flags
        resp.set_cookie(
            "ab_session",
            "1",
            max_age=14 * 24 * 3600,
            httponly=True,
            samesite="Lax",
            secure=app.config["SESSION_COOKIE_SECURE"],
        )
        return resp

    # Example Firestore read (requires ADC)
    @app.route("/api/example-doc", methods=["GET"]) 
    def example_doc():
        try:
            from firestore_client import get_db

            db = get_db()
            doc_ref = db.collection("athlete-buddy").document("example")
            doc = doc_ref.get()
            if doc.exists:
                return jsonify({"id": doc.id, **doc.to_dict()})
            return jsonify({"id": doc_ref.id, "message": "no data"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # --- Open-Meteo proxy endpoints ---
    @app.route("/api/geocode", methods=["GET"])  # ?q=City
    def geocode():
        query = request.args.get("q", "").strip()
        if not query:
            return jsonify({"error": "Missing q"}), 400
        try:
            def geocode_request(q: str):
                resp = requests.get(
                    "https://geocoding-api.open-meteo.com/v1/search",
                    params={"name": q, "count": 5, "language": "en", "format": "json"},
                    timeout=8,
                )
                resp.raise_for_status()
                payload = resp.json()
                return payload.get("results") or []

            results = geocode_request(query)
            if not results and "," in query:
                primary = query.split(",")[0].strip()
                if primary:
                    results = geocode_request(primary)
            if not results:
                simplified_q = query.replace(",", " ").replace("  ", " ").strip()
                if simplified_q and simplified_q != query:
                    results = geocode_request(simplified_q)

            simplified = [
                {
                    "name": item.get("name"),
                    "country": item.get("country"),
                    "admin1": item.get("admin1"),
                    "latitude": item.get("latitude"),
                    "longitude": item.get("longitude"),
                }
                for item in results
            ]
            return jsonify({"results": simplified})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/reverse", methods=["GET"])  # ?lat=&lon=
    def reverse_geocode():
        lat = request.args.get("lat")
        lon = request.args.get("lon")
        if not lat or not lon:
            return jsonify({"error": "Missing lat/lon"}), 400
        try:
            # Provider 1: Open-Meteo (sometimes returns 404 for reverse)
            try:
                r = requests.get(
                    "https://geocoding-api.open-meteo.com/v1/reverse",
                    params={"latitude": lat, "longitude": lon, "language": "en", "format": "json"},
                    timeout=8,
                )
                r.raise_for_status()
                data = r.json()
                results = data.get("results") or []
                if results:
                    item = results[0]
                    return jsonify({
                        "name": item.get("name"),
                        "admin1": item.get("admin1"),
                        "country": item.get("country"),
                        "latitude": item.get("latitude"),
                        "longitude": item.get("longitude"),
                    })
            except Exception:
                pass

            # Fallback: OpenStreetMap Nominatim (no key, rate-limited; add UA)
            r2 = requests.get(
                "https://nominatim.openstreetmap.org/reverse",
                params={"format": "jsonv2", "lat": lat, "lon": lon, "accept-language": "en"},
                headers={"User-Agent": "athlete-buddy/1.0 (contact: dev@example.com)"},
                timeout=10,
            )
            r2.raise_for_status()
            d2 = r2.json()
            address = (d2 or {}).get("address") or {}
            name = d2.get("name") or address.get("city") or address.get("town") or address.get("village") or address.get("hamlet") or "Unknown"
            admin1 = address.get("state")
            country = address.get("country")
            return jsonify({
                "name": name,
                "admin1": admin1,
                "country": country,
                "latitude": float(lat),
                "longitude": float(lon),
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # --- Minimal Google Sign-In verification ---
    @app.route("/api/auth/google", methods=["POST"])  
    def auth_google():
        try:
            payload = request.get_json(silent=True) or {}
            token = payload.get("id_token")
            if not token:
                return jsonify({"error": "Missing id_token"}), 400
            request_adapter = google_requests.Request()
            aud = os.environ.get("GOOGLE_CLIENT_ID")
            idinfo = google_id_token.verify_oauth2_token(token, request_adapter, audience=aud if aud else None)
            sub = idinfo.get("sub")
            if not sub:
                return jsonify({"error": "Invalid token"}), 401
            # Include basic profile data such as the user's picture when available
            resp = make_response(
                jsonify(
                    {
                        "ok": True,
                        "user": {
                            "sub": sub,
                            "email": idinfo.get("email"),
                            "name": idinfo.get("name"),
                            "picture": idinfo.get("picture"),
                        },
                    }
                )
            )
            resp.set_cookie(
                "ab_uid",
                sub,
                max_age=30 * 24 * 3600,
                httponly=True,
                samesite="Lax",
                secure=app.config["SESSION_COOKIE_SECURE"],
            )
            return resp
        except Exception as e:
            return jsonify({"error": str(e)}), 401

    @app.route("/api/auth/logout", methods=["POST"])  
    def auth_logout():
        resp = make_response(jsonify({"ok": True}))
        resp.set_cookie("ab_uid", "", max_age=0)
        return resp

    # --- Preferences (Firestore) ---
    def _require_user_id():
        uid = request.cookies.get("ab_uid")
        if not uid:
            return None
        return uid

    # --- Local dev store (fallback when Firestore/ADC not available) ---
    _dev_store_path = os.path.join(os.path.dirname(__file__), ".devdata.json")

    def _dev_store_read() -> dict:
        try:
            import json
            if os.path.exists(_dev_store_path):
                with open(_dev_store_path, "r", encoding="utf-8") as f:
                    return json.load(f) or {}
        except Exception:
            pass
        return {}

    def _dev_store_write(payload: dict) -> None:
        try:
            import json
            with open(_dev_store_path, "w", encoding="utf-8") as f:
                json.dump(payload, f)
        except Exception:
            pass

    @app.route("/api/preferences", methods=["GET"])  
    def get_preferences():
        uid = _require_user_id()
        if not uid:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            from firestore_client import get_db
            db = get_db()
            doc_ref = db.collection("ab_prefs").document(uid)
            doc = doc_ref.get()
            if not doc.exists:
                return jsonify({"preferences": {}})
            return jsonify({"preferences": doc.to_dict()})
        except Exception as e:
            # Fallback to local dev store
            store = _dev_store_read()
            prefs = (store.get("prefs") or {}).get(uid) or {}
            return jsonify({"preferences": prefs})

    @app.route("/api/preferences", methods=["PUT"])  
    def put_preferences():
        uid = _require_user_id()
        if not uid:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            prefs = request.get_json(silent=True) or {}
            from firestore_client import get_db
            db = get_db()
            db.collection("ab_prefs").document(uid).set(prefs, merge=True)
            return jsonify({"ok": True})
        except Exception as e:
            # Fallback to local dev store
            store = _dev_store_read()
            prefs_by_user = store.get("prefs") or {}
            existing = (prefs_by_user.get(uid) or {})
            existing.update(prefs)
            prefs_by_user[uid] = existing
            store["prefs"] = prefs_by_user
            _dev_store_write(store)
            return jsonify({"ok": True, "devStore": True})

    # --- Social: Friends ---
    @app.route("/api/friends", methods=["GET", "POST", "DELETE"])  
    def friends():
        uid = _require_user_id()
        if not uid:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            from firestore_client import get_db
            from google.cloud import firestore  # for ArrayUnion/ArrayRemove
            db = get_db()
            doc_ref = db.collection("ab_friends").document(uid)
            if request.method == "GET":
                doc = doc_ref.get()
                data = doc.to_dict() if doc.exists else {}
                return jsonify({"friends": data.get("friends", [])})
            payload = request.get_json(silent=True) or {}
            friend = (payload.get("friend") or "").strip()
            if not friend:
                return jsonify({"error": "Missing friend"}), 400
            if request.method == "POST":
                doc_ref.set({"friends": firestore.ArrayUnion([friend])}, merge=True)
                return jsonify({"ok": True})
            if request.method == "DELETE":
                doc_ref.set({"friends": firestore.ArrayRemove([friend])}, merge=True)
                return jsonify({"ok": True})
            return jsonify({"error": "Unsupported method"}), 405
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # --- Social: Activity Feed (placeholder) ---
    @app.route("/api/feed", methods=["GET"])  
    def feed():
        uid = _require_user_id()
        if not uid:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            from firestore_client import get_db
            db = get_db()
            # Expect a single document with an array field `items` for simplicity
            doc = db.collection("ab_feed").document(uid).get()
            items = []
            if doc.exists:
                data = doc.to_dict() or {}
                items = data.get("items", [])
            return jsonify({"items": items})
        except Exception:
            # Fallback to local dev store if Firestore/ADC unavailable
            store = _dev_store_read()
            user_feed = (store.get("feed") or {}).get(uid) or {}
            return jsonify({"items": user_feed.get("items", [])})

    # --- Activities (create/list) ---
    @app.route("/api/activities", methods=["GET", "POST"])  
    def activities():
        uid = _require_user_id()
        if not uid:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            from firestore_client import get_db
            from google.cloud import firestore  # for ArrayUnion
            db = get_db()

            if request.method == "GET":
                doc = db.collection("ab_activities").document(uid).get()
                items = []
                if doc.exists:
                    data = doc.to_dict() or {}
                    items = data.get("items", [])
                # Sort desc by timestamp if present
                try:
                    items = sorted(items, key=lambda x: x.get("timestamp") or 0, reverse=True)
                except Exception:
                    pass
                return jsonify({"items": items})

            # POST (multipart form)
            planned_time = request.form.get("planned_time") or None
            speed = request.form.get("speed") or None
            interested = request.form.get("interested") or "false"
            try:
                interested_bool = str(interested).lower() in ["1", "true", "yes", "on"]
            except Exception:
                interested_bool = False
            import json as _json
            route = None
            route_json = request.form.get("route_json")
            if route_json:
                try:
                    route = _json.loads(route_json)
                except Exception:
                    route = None
            creator_picture = request.form.get("creator_picture") or None
            gpx_name = None
            gpx_size = None
            if "gpx" in request.files:
                f = request.files["gpx"]
                try:
                    from werkzeug.utils import secure_filename
                    gpx_name = secure_filename(f.filename or "")
                except Exception:
                    gpx_name = f.filename or None
                try:
                    # Peek length if provided by client; avoid consuming stream
                    gpx_size = getattr(f, "content_length", None)
                except Exception:
                    gpx_size = None

            import time as _time
            now_ms = int(_time.time() * 1000)
            item = {
                "id": str(now_ms),
                "friend": "You",
                "activity": "Planned route",
                "timestamp": planned_time or None,
                "speed": speed,
                "interested": interested_bool,
                "gpx_name": gpx_name,
                "route": route,
                "creator_picture": creator_picture,
                "gpx_size": gpx_size,
            }
            # Normalize timestamp to ISO if provided
            if planned_time:
                try:
                    # Accepts HTML datetime-local string; store raw string
                    item["timestamp"] = planned_time
                except Exception:
                    pass

            db.collection("ab_activities").document(uid).set({
                "items": firestore.ArrayUnion([item])
            }, merge=True)
            return jsonify({"ok": True, "item": item})
        except Exception:
            # Dev fallback
            store = _dev_store_read()
            activities = store.get("activities") or {}
            user_doc = activities.get(uid) or {"items": []}
            import time as _time
            now_ms = int(_time.time() * 1000)
            planned_time = request.form.get("planned_time") or None
            speed = request.form.get("speed") or None
            interested = request.form.get("interested") or "false"
            try:
                interested_bool = str(interested).lower() in ["1", "true", "yes", "on"]
            except Exception:
                interested_bool = False
            route = None
            creator_picture = request.form.get("creator_picture") or None
            gpx_name = None
            if "gpx" in request.files:
                f = request.files["gpx"]
                gpx_name = getattr(f, "filename", None)
            item = {
                "id": str(now_ms),
                "friend": "You",
                "activity": "Planned route",
                "timestamp": planned_time or None,
                "speed": speed,
                "interested": interested_bool,
                "gpx_name": gpx_name,
                "route": route,
                "creator_picture": creator_picture,
            }
            user_doc_items = user_doc.get("items") or []
            user_doc_items.insert(0, item)
            user_doc["items"] = user_doc_items
            activities[uid] = user_doc
            store["activities"] = activities
            _dev_store_write(store)
            return jsonify({"ok": True, "item": item, "devStore": True})

    # --- Activity Chat ---
    @app.route("/api/chat/<activity_id>", methods=["GET", "POST"])  
    def activity_chat(activity_id: str):
        uid = _require_user_id()
        if not uid:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            from firestore_client import get_db
            from google.cloud import firestore  # for ArrayUnion
            db = get_db()
            doc_ref = db.collection("ab_chat").document(activity_id)
            if request.method == "GET":
                doc = doc_ref.get()
                msgs = []
                if doc.exists:
                    data = doc.to_dict() or {}
                    msgs = data.get("messages", [])
                return jsonify({"messages": msgs})
            payload = request.get_json(silent=True) or {}
            text = (payload.get("text") or "").strip()
            if not text:
                return jsonify({"error": "Missing text"}), 400
            import time as _time
            msg = {"from": uid, "text": text, "ts": int(_time.time() * 1000)}
            doc_ref.set({"messages": firestore.ArrayUnion([msg])}, merge=True)
            return jsonify({"ok": True})
        except Exception:
            # Dev fallback
            store = _dev_store_read()
            chats = store.get("chats") or {}
            thread = chats.get(activity_id) or {"messages": []}
            if request.method == "GET":
                return jsonify({"messages": thread.get("messages", [])})
            payload = request.get_json(silent=True) or {}
            text = (payload.get("text") or "").strip()
            if not text:
                return jsonify({"error": "Missing text"}), 400
            import time as _time
            msg = {"from": uid, "text": text, "ts": int(_time.time() * 1000)}
            msgs = thread.get("messages") or []
            msgs.append(msg)
            thread["messages"] = msgs
            chats[activity_id] = thread
            store["chats"] = chats
            _dev_store_write(store)
            return jsonify({"ok": True, "devStore": True})

    # --- Strava OAuth ---
    def _strava_client_config():
        client_id = os.environ.get("STRAVA_CLIENT_ID")
        client_secret = os.environ.get("STRAVA_CLIENT_SECRET")
        redirect_uri = os.environ.get("STRAVA_REDIRECT_URI", "http://127.0.0.1:5050/api/auth/strava/callback")
        if not client_id or not client_secret:
            return None
        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        }

    @app.route("/api/auth/strava/start", methods=["GET"])  
    def strava_start():
        uid = _require_user_id()
        if not uid:
            return jsonify({"error": "Unauthorized"}), 401
        cfg = _strava_client_config()
        if not cfg:
            return jsonify({"error": "Strava is not configured"}), 500
        # CSRF state
        signer = URLSafeSerializer(app.config["SECRET_KEY"], salt="strava_state")
        state = signer.dumps({"uid": uid})
        scope = request.args.get("scope", "read,activity:read_all")
        auth_url = (
            "https://www.strava.com/oauth/authorize"
            f"?client_id={cfg['client_id']}"
            f"&response_type=code&redirect_uri={cfg['redirect_uri']}"
            f"&scope={scope}&state={state}&approval_prompt=auto"
        )
        return redirect(auth_url, code=302)

    @app.route("/api/auth/strava/callback", methods=["GET"])  
    def strava_callback():
        code = request.args.get("code")
        state = request.args.get("state")
        if not code or not state:
            return jsonify({"error": "Missing code/state"}), 400
        # Verify state
        try:
            signer = URLSafeSerializer(app.config["SECRET_KEY"], salt="strava_state")
            data = signer.loads(state)
            uid = (data or {}).get("uid")
        except Exception:
            return jsonify({"error": "Invalid state"}), 400
        if not uid:
            return jsonify({"error": "Invalid user"}), 400
        cfg = _strava_client_config()
        if not cfg:
            return jsonify({"error": "Strava is not configured"}), 500
        try:
            resp = requests.post(
                "https://www.strava.com/oauth/token",
                data={
                    "client_id": cfg["client_id"],
                    "client_secret": cfg["client_secret"],
                    "code": code,
                    "grant_type": "authorization_code",
                },
                timeout=10,
            )
            resp.raise_for_status()
            token_payload = resp.json() or {}
            access_token = token_payload.get("access_token")
            refresh_token = token_payload.get("refresh_token")
            expires_at = token_payload.get("expires_at")
            athlete = token_payload.get("athlete") or {}

            from firestore_client import get_db
            db = get_db()
            db.collection("ab_integrations").document(uid).set(
                {
                    "strava": {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "expires_at": expires_at,
                        "athlete": {"id": athlete.get("id"), "username": athlete.get("username"), "firstname": athlete.get("firstname"), "lastname": athlete.get("lastname")},
                        "connected_at": int(__import__("time").time()),
                    }
                },
                merge=True,
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        # Redirect back to frontend
        frontend = os.environ.get("FRONTEND_ORIGIN", "http://127.0.0.1:5173")
        return redirect(f"{frontend}/?strava=connected", code=302)

    @app.route("/api/integrations/strava", methods=["GET"])  
    def strava_status():
        uid = _require_user_id()
        if not uid:
            return jsonify({"connected": False})
        try:
            from firestore_client import get_db
            db = get_db()
            doc = db.collection("ab_integrations").document(uid).get()
            data = doc.to_dict() if doc.exists else {}
            s = (data or {}).get("strava") or {}
            return jsonify({
                "connected": bool(s.get("access_token")),
                "expires_at": s.get("expires_at"),
                "athlete": (s.get("athlete") or {}).get("username") or (s.get("athlete") or {}).get("id"),
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    @app.route("/api/forecast", methods=["GET"])  # ?lat=&lon=&units=imperial|metric
    def forecast():
        try:
            lat = request.args.get("lat")
            lon = request.args.get("lon")
            units = (request.args.get("units") or "imperial").lower()
            if not lat or not lon:
                return jsonify({"error": "Missing lat/lon"}), 400
            temp_unit = "fahrenheit" if units == "imperial" else "celsius"
            wind_unit = "mph" if units == "imperial" else "kmh"
            r = requests.get(
                "https://api.open-meteo.com/v1/forecast",
                params={
                    "latitude": lat,
                    "longitude": lon,
                    "current": [
                        "temperature_2m",
                        "apparent_temperature",
                        "relative_humidity_2m",
                        "wind_speed_10m",
                        "wind_direction_10m",
                        "visibility",
                        "uv_index",
                        "pressure_msl",
                        "precipitation",
                        "weather_code",
                    ],
                    "hourly": [
                        "temperature_2m",
                        "precipitation_probability",
                        "weather_code",
                        "visibility",
                        "uv_index",
                        "is_day",
                        "relative_humidity_2m",
                        "wind_speed_10m",
                    ],
                    "daily": ["temperature_2m_max", "temperature_2m_min", "precipitation_sum", "weather_code", "sunrise", "sunset"],
                    "temperature_unit": temp_unit,
                    "wind_speed_unit": wind_unit,
                    "timezone": "auto",
                },
                timeout=10,
            )
            r.raise_for_status()
            data = r.json()
            # Lightly normalize
            payload = {
                "current": data.get("current", {}),
                "hourly": {
                    "time": (data.get("hourly") or {}).get("time", []),
                    "temperature_2m": (data.get("hourly") or {}).get("temperature_2m", []),
                    "precipitation_probability": (data.get("hourly") or {}).get("precipitation_probability", []),
                    "weather_code": (data.get("hourly") or {}).get("weather_code", []),
                    "is_day": (data.get("hourly") or {}).get("is_day", []),
                    "relative_humidity_2m": (data.get("hourly") or {}).get("relative_humidity_2m", []),
                    "wind_speed_10m": (data.get("hourly") or {}).get("wind_speed_10m", []),
                    "uv_index": (data.get("hourly") or {}).get("uv_index", []),
                },
                "daily": {
                    "time": (data.get("daily") or {}).get("time", []),
                    "temperature_2m_max": (data.get("daily") or {}).get("temperature_2m_max", []),
                    "temperature_2m_min": (data.get("daily") or {}).get("temperature_2m_min", []),
                    "precipitation_sum": (data.get("daily") or {}).get("precipitation_sum", []),
                    "weather_code": (data.get("daily") or {}).get("weather_code", []),
                    "sunrise": (data.get("daily") or {}).get("sunrise", []),
                    "sunset": (data.get("daily") or {}).get("sunset", []),
                },
                "units": units,
                "timezone": data.get("timezone"),
                "timezone_abbreviation": data.get("timezone_abbreviation"),
            }
            return jsonify(payload)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    # Debug server for local dev; use Gunicorn in production
    app.run(host="127.0.0.1", port=5050, debug=True)


