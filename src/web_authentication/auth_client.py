"""
auth_client.py - Exercises every mechanism of the example server
and also checks the auth_utils functions against the RFC test vectors.

Usage: python3 auth_client.py   (with auth_server.py running)
"""
import base64
import json
import os
import sys

import requests

from auth_utils import (challenge_s256, generate_pkce, hash_password, totp,
                        verify_password)

PORT = int(os.environ.get("AUTH_PORT", "5443"))
BASE = f"https://localhost:{PORT}"
TOTP_SECRET = os.environ.get("TOTP_SECRET", "JBSWY3DPEHPK3PXP")
CA = "ca.pem"                       # The server certificate is verified
failures = 0


def check(description, condition, detail=""):
    global failures
    status = "OK    " if condition else "FAIL  "
    if not condition:
        failures += 1
    print(f"[{status}] {description}" + (f"  ({detail})" if detail else ""))


def decode_jwt(token):
    """For display only: does NOT verify the signature."""
    def part(p):
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    header, payload, _ = token.split(".")
    return part(header), part(payload)


# --- 1. Local functions against the RFC test vectors ------------------------

print("== auth_utils functions")
h = hash_password("secret")
check("salted Argon2id hash", h.startswith("$argon2id$"), h[:30] + "...")
check("two hashes of the same password differ", h != hash_password("secret"))
check("accepts the correct password", verify_password(h, "secret")[0])
check("rejects a wrong one", not verify_password(h, "other")[0])

# RFC 6238, appendix B: secret "12345678901234567890", T=59 s -> 94287082
rfc_secret = base64.b32encode(b"12345678901234567890").decode()
check("TOTP matches the RFC 6238 test vector",
      totp(rfc_secret, at=59, digits=8) == "94287082")

# RFC 7636, appendix B
check("PKCE S256 matches the RFC 7636 test vector",
      challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
      == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
verifier, challenge = generate_pkce()
check("PKCE generates a 43-character code_verifier", len(verifier) == 43,
      f"challenge={challenge[:12]}...")

# --- 2. Cookie session + TOTP --------------------------------------------------

print("\n== Cookie session and second factor")
s = requests.Session()
s.verify = CA
s.trust_env = False                 # Ignore proxies and REQUESTS_CA_BUNDLE from the environment
s.headers["Origin"] = BASE          # As a browser on our own site would

r = s.post(f"{BASE}/login", json={"username": "juan", "password": "wrong"})
check("wrong password -> 401", r.status_code == 401)
r = s.post(f"{BASE}/login", json={"username": "nobody", "password": "x"})
check("unknown user -> same 401 and same message",
      r.status_code == 401 and r.json()["error"] == "wrong username or password")

r = s.post(f"{BASE}/login", json={"username": "juan",
                                  "password": "correct-horse-battery-staple"})
cookie_1 = s.cookies.get("__Host-session")
check("correct password -> asks for second factor", r.json().get("mfa_required") is True)
set_cookie = r.headers.get("Set-Cookie", "")
check("cookie with Secure, HttpOnly and SameSite=Lax",
      all(a in set_cookie for a in ("Secure", "HttpOnly", "SameSite=Lax")),
      set_cookie.split(";")[0][:30] + "...")

r = s.get(f"{BASE}/profile")
check("no access to /profile without second factor", r.status_code == 401)

r = s.post(f"{BASE}/login/mfa", json={"code": "000000"})
check("wrong TOTP code -> 401", r.status_code == 401)
code = totp(TOTP_SECRET)
r = s.post(f"{BASE}/login/mfa", json={"code": code})
cookie_2 = s.cookies.get("__Host-session")
check("correct TOTP code -> full session", r.status_code == 200, f"code {code}")
check("session ID changes on authentication (anti-fixation)", cookie_1 != cookie_2)

r = s.get(f"{BASE}/profile")
check("/profile with session", r.status_code == 200, r.text.strip())

r = s.post(f"{BASE}/logout", headers={"Origin": "https://attacker.example"})
check("CSRF: POST from another origin -> 403", r.status_code == 403)

# --- 3. API tokens ---------------------------------------------------------------

print("\n== JWT access token and refresh token")
r = s.post(f"{BASE}/api/token")
t = r.json()
access, refresh = t["access_token"], t["refresh_token"]
header, payload = decode_jwt(access)
check("access and refresh tokens issued", r.status_code == 200,
      f"alg={header['alg']}, exp-iat={payload['exp'] - payload['iat']} s, scope={payload['scope']}")

api = requests.Session()
api.verify = CA
api.trust_env = False
r = api.get(f"{BASE}/api/orders")
check("API without token -> 401", r.status_code == 401)
r = api.get(f"{BASE}/api/orders", headers={"Authorization": f"Bearer {access}"})
check("API with token -> 200", r.status_code == 200, r.text.strip())

# alg=none attack: same payload, no signature
forged = (base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
          + "." + access.split(".")[1] + ".")
r = api.get(f"{BASE}/api/orders", headers={"Authorization": f"Bearer {forged}"})
check("token with alg=none -> rejected", r.status_code == 401, r.json()["error"][:45])

# Modified payload: the signature no longer matches
hdr, pld, sig = access.split(".")
modified = dict(payload, sub="admin")
pld_mod = base64.urlsafe_b64encode(json.dumps(modified).encode()).rstrip(b"=").decode()
r = api.get(f"{BASE}/api/orders",
            headers={"Authorization": f"Bearer {hdr}.{pld_mod}.{sig}"})
check("token with changed sub -> rejected", r.status_code == 401)

r = api.post(f"{BASE}/api/refresh", json={"refresh_token": refresh})
new_refresh = r.json().get("refresh_token")
check("refresh -> new token pair", r.status_code == 200 and new_refresh != refresh)
r = api.post(f"{BASE}/api/refresh", json={"refresh_token": refresh})
check("reusing the old refresh token -> 401", r.status_code == 401, r.json()["error"])
r = api.post(f"{BASE}/api/refresh", json={"refresh_token": new_refresh})
check("after reuse, the whole family is revoked", r.status_code == 401)

# --- 4. Logout ---------------------------------------------------------------------

print("\n== Logout")
r = s.post(f"{BASE}/logout")
check("logout -> 200", r.status_code == 200)
fresh = requests.Session()
fresh.verify, fresh.trust_env = CA, False
r = fresh.get(f"{BASE}/profile", cookies={"__Host-session": cookie_2})
check("the old cookie no longer works (session deleted on the server)", r.status_code == 401)

print(f"\n{'All checks passed' if failures == 0 else f'{failures} checks failed'}")
sys.exit(1 if failures else 0)
