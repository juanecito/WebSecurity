"""
auth_server.py - Example server with:
  * password login (Argon2id) + TOTP second factor
  * server-side session with a __Host- cookie, regenerated on authentication
  * CSRF defence by checking the Origin header
  * JWT access token + rotating refresh token issued for an API

Usage: python3 auth_server.py   (HTTPS on https://localhost:5443)
For learning only: in-memory data and a single test user.
"""
import os
import secrets
import time
from functools import wraps

from flask import Flask, g, jsonify, request

from auth_utils import (TokenError, TokenIssuer, hash_password,
                        verify_password, verify_totp)

PORT = int(os.environ.get("AUTH_PORT", "5443"))
ORIGIN = f"https://localhost:{PORT}"
COOKIE = "__Host-session"
IDLE_TIMEOUT = 30 * 60         # Idle logout: 30 minutes
MAX_LIFETIME = 12 * 3600       # Absolute logout: 12 hours
MAX_FAILURES, LOCKOUT = 5, 60  # 5 failed attempts -> locked for 60 s

app = Flask(__name__)

# In-memory "database". The password only exists as a hash.
USERS = {
    "juan": {
        "hash": hash_password("correct-horse-battery-staple"),
        "totp": os.environ.get("TOTP_SECRET", "JBSWY3DPEHPK3PXP"),
        "last_totp_step": None,
        "scope": "orders:read",
        "failures": 0,
        "locked_until": 0,
    }
}
SESSIONS = {}   # session id -> data
tokens = TokenIssuer(issuer=ORIGIN, audience=ORIGIN + "/api")


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------

def create_session(user, mfa_ok):
    sid = secrets.token_urlsafe(32)          # 256 random bits
    now = time.time()
    SESSIONS[sid] = {"user": user, "mfa_ok": mfa_ok,
                     "created": now, "last_seen": now}
    return sid


def set_cookie(response, sid):
    response.set_cookie(COOKIE, sid, path="/", secure=True, httponly=True,
                        samesite="Lax", max_age=MAX_LIFETIME)
    return response


def current_session():
    sid = request.cookies.get(COOKIE)
    data = SESSIONS.get(sid) if sid else None
    if not data:
        return None, None
    now = time.time()
    if (now - data["last_seen"] > IDLE_TIMEOUT
            or now - data["created"] > MAX_LIFETIME):
        SESSIONS.pop(sid, None)
        return None, None
    data["last_seen"] = now
    return sid, data


def require_session(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        sid, data = current_session()
        if not data or not data["mfa_ok"]:
            return jsonify(error="not authenticated"), 401
        g.sid, g.user = sid, data["user"]
        return f(*args, **kwargs)
    return wrapper


def require_token(scope):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify(error="missing token"), 401, \
                    {"WWW-Authenticate": 'Bearer realm="api"'}
            try:
                claims = tokens.validate_access(header[7:])
            except TokenError as e:
                return jsonify(error=str(e)), 401, \
                    {"WWW-Authenticate": 'Bearer error="invalid_token"'}
            if scope not in claims.get("scope", "").split():
                return jsonify(error="insufficient scope"), 403
            g.claims = claims
            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.before_request
def csrf_defence():
    # Browsers send Origin on state-changing requests.
    # If it comes from another site, reject it. (SameSite=Lax is the first barrier.)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("Origin")
        if origin is not None and origin != ORIGIN:
            return jsonify(error="origin not allowed"), 403


# --------------------------------------------------------------------------
# Password + TOTP login
# --------------------------------------------------------------------------

@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    name, password = data.get("username", ""), data.get("password", "")
    user = USERS.get(name)

    if user and user["locked_until"] > time.time():
        return jsonify(error="too many attempts, wait"), 429

    ok, new_hash = verify_password(user["hash"] if user else None, password)
    if not ok:
        if user:
            user["failures"] += 1
            if user["failures"] >= MAX_FAILURES:
                user["locked_until"] = time.time() + LOCKOUT
                user["failures"] = 0
        # Same message whether or not the user exists
        return jsonify(error="wrong username or password"), 401

    user["failures"] = 0
    if new_hash:
        user["hash"] = new_hash

    # Against session fixation: discard any previous session
    # and create a new identifier.
    old_sid = request.cookies.get(COOKIE)
    SESSIONS.pop(old_sid, None)
    sid = create_session(name, mfa_ok=False)
    return set_cookie(jsonify(mfa_required=True), sid)


@app.post("/login/mfa")
def login_mfa():
    sid, data = current_session()
    if not data:
        return jsonify(error="log in first"), 401
    user = USERS[data["user"]]
    code = (request.get_json(silent=True) or {}).get("code", "")

    step = verify_totp(user["totp"], code, user["last_totp_step"])
    if step is None:
        return jsonify(error="wrong code"), 401
    user["last_totp_step"] = step              # A code cannot be reused

    # Privilege change: new session identifier again.
    SESSIONS.pop(sid, None)
    new_sid = create_session(data["user"], mfa_ok=True)
    return set_cookie(jsonify(ok=True), new_sid)


@app.get("/profile")
@require_session
def profile():
    return jsonify(user=g.user)


@app.post("/logout")
def logout():
    sid = request.cookies.get(COOKIE)
    SESSIONS.pop(sid, None)                    # Deleted on the server
    response = jsonify(ok=True)
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True,
                           samesite="Lax")
    return response


# --------------------------------------------------------------------------
# Token-protected API
# --------------------------------------------------------------------------

@app.post("/api/token")
@require_session
def issue_tokens():
    """Give tokens to an already authenticated user (for example, for a CLI)."""
    scope = USERS[g.user]["scope"]
    return jsonify(access_token=tokens.issue_access(g.user, scope),
                   refresh_token=tokens.issue_refresh(g.user, scope),
                   token_type="Bearer", expires_in=tokens.access_ttl)


@app.post("/api/refresh")
def refresh_tokens():
    refresh = (request.get_json(silent=True) or {}).get("refresh_token", "")
    try:
        access, new_refresh = tokens.refresh(refresh)
    except TokenError as e:
        return jsonify(error=str(e)), 401
    return jsonify(access_token=access, refresh_token=new_refresh,
                   token_type="Bearer", expires_in=tokens.access_ttl)


@app.get("/api/orders")
@require_token("orders:read")
def orders():
    return jsonify(user=g.claims["sub"], orders=[{"id": 1, "total": 42.5}])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT,
            ssl_context=("server.pem", "server.key"))
