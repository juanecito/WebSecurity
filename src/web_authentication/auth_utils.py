"""
auth_utils.py - Reusable authentication building blocks:
passwords with Argon2id, TOTP (RFC 6238), PKCE (RFC 7636) and
JWT access tokens with rotating refresh tokens.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives.asymmetric import ec


# --------------------------------------------------------------------------
# Passwords: Argon2id with a random salt (the library generates it and stores
# it inside the hash string itself).
# --------------------------------------------------------------------------

_ph = PasswordHasher()                       # Argon2id, RFC 9106 parameters
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash, password: str):
    """Return (valid, new_hash).

    new_hash is not None when the stored parameters are outdated and the
    hash in the database should be updated.
    """
    if stored_hash is None:
        # The user does not exist: compute a hash anyway so the response
        # time does not reveal which users exist.
        try:
            _ph.verify(_DUMMY_HASH, password)
        except VerifyMismatchError:
            pass
        return False, None

    try:
        _ph.verify(stored_hash, password)     # Constant-time comparison
    except (VerifyMismatchError, InvalidHashError):
        return False, None

    new_hash = _ph.hash(password) if _ph.check_needs_rehash(stored_hash) else None
    return True, new_hash


# --------------------------------------------------------------------------
# TOTP (RFC 6238): the same computation authenticator apps perform.
# --------------------------------------------------------------------------

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()   # 160 bits


def totp(secret_b32: str, at=None, step=30, digits=6) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F                             # Dynamic truncation
    number = struct.unpack(">I", mac[offset:offset + 4])[0]
    return str((number & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def verify_totp(secret_b32: str, code: str, last_used_step=None,
                window=1, step=30):
    """Return the accepted step number, or None.

    Accepts the current interval and `window` intervals before and after
    (clock skew), and rejects codes from steps already used.
    """
    now = int(time.time() // step)
    for s in range(now - window, now + window + 1):
        if last_used_step is not None and s <= last_used_step:
            continue
        if hmac.compare_digest(totp(secret_b32, s * step, step), code):
            return s
    return None


def totp_uri(secret_b32: str, user: str, issuer: str) -> str:
    """URI shown as a QR code when enrolling the second factor."""
    return f"otpauth://totp/{issuer}:{user}?secret={secret_b32}&issuer={issuer}"


# --------------------------------------------------------------------------
# PKCE (RFC 7636)
# --------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def challenge_s256(code_verifier: str) -> str:
    return b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())


def generate_pkce():
    """Return (code_verifier, code_challenge)."""
    code_verifier = b64url(secrets.token_bytes(32))     # 43 characters
    return code_verifier, challenge_s256(code_verifier)


# --------------------------------------------------------------------------
# Tokens: JWT access token (ES256, short-lived) + rotating opaque refresh token
# --------------------------------------------------------------------------

class TokenError(Exception):
    pass


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class TokenIssuer:
    def __init__(self, issuer, audience, access_ttl=900, refresh_ttl=7 * 86400):
        self.issuer = issuer
        self.audience = audience
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl
        # Elliptic-curve key pair: sign with the private key and any
        # service can verify with the public one.
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.kid = secrets.token_hex(4)
        # Refresh tokens are stored by their hash, never in the clear.
        self._refresh = {}
        self._revoked_families = set()

    # --- Access token -----------------------------------------------------

    def issue_access(self, sub: str, scope: str) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": sub,
            "aud": self.audience,
            "iat": now,
            "exp": now + self.access_ttl,
            "jti": secrets.token_hex(8),
            "scope": scope,
        }
        return jwt.encode(claims, self.private_key, algorithm="ES256",
                          headers={"kid": self.kid})

    def validate_access(self, token: str) -> dict:
        try:
            return jwt.decode(
                token,
                self.public_key,
                algorithms=["ES256"],          # Fixed: never the one the token names
                audience=self.audience,
                issuer=self.issuer,
                leeway=30,                     # Allowance for clock skew
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.InvalidTokenError as e:
            raise TokenError(f"invalid access token: {e}") from e

    # --- Refresh token ----------------------------------------------------

    def issue_refresh(self, sub: str, scope: str, family=None) -> str:
        token = "rt_" + secrets.token_urlsafe(32)
        self._refresh[_sha256(token)] = {
            "sub": sub,
            "scope": scope,
            "family": family or secrets.token_hex(8),
            "used": False,
            "exp": time.time() + self.refresh_ttl,
        }
        return token

    def refresh(self, refresh_token: str):
        """Exchange a refresh token for a new (access, refresh) pair and invalidate it."""
        data = self._refresh.get(_sha256(refresh_token))
        if (data is None or data["exp"] < time.time()
                or data["family"] in self._revoked_families):
            raise TokenError("invalid refresh token")
        if data["used"]:
            # Reuse: someone has a copy. Revoke the whole family.
            self._revoked_families.add(data["family"])
            raise TokenError("refresh token reused: session revoked")
        data["used"] = True
        return (self.issue_access(data["sub"], data["scope"]),
                self.issue_refresh(data["sub"], data["scope"], data["family"]))

    def revoke(self, refresh_token: str):
        data = self._refresh.get(_sha256(refresh_token))
        if data:
            self._revoked_families.add(data["family"])
