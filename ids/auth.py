"""Passwords, session tokens and API keys.

Rules this file follows (these are the answers to "how do you store passwords?"):
  * Passwords are never stored. We store a salted scrypt hash (slow on purpose, so
    guessing millions of passwords per second is impossible).
  * Session tokens and API keys are random 256-bit values. We store only their
    SHA-256 hash, so a leaked database cannot be used to log in or send data.
  * Comparisons use hmac.compare_digest (constant time).
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
MIN_PASSWORD, MAX_PASSWORD = 10, 128
API_KEY_PREFIX = "gk_"

_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
_dummy: str | None = None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                            p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=int(n),
                                r=int(r), p=int(p), dklen=len(bytes.fromhex(digest_hex)))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def dummy_hash() -> str:
    """Hash to check against when the email does not exist, so a missing account takes
    as long to reject as a wrong password (no account-enumeration by timing)."""
    global _dummy
    if _dummy is None:
        _dummy = hash_password(secrets.token_urlsafe(16))
    return _dummy


def validate_email(email: str) -> bool:
    return len(email) <= 254 and bool(_EMAIL.match(email))


def validate_password(password: str) -> str | None:
    """Returns an error message, or None if the password is acceptable."""
    if len(password) < MIN_PASSWORD:
        return f"Password must be at least {MIN_PASSWORD} characters."
    if len(password) > MAX_PASSWORD:
        return f"Password must be at most {MAX_PASSWORD} characters."
    if password.lower() in {"password12", "1234567890", "qwertyuiop", "password123"}:
        return "That password is too common."
    return None


def new_token() -> str:
    return secrets.token_urlsafe(32)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_api_key() -> tuple[str, str, str]:
    """Returns (key, display_prefix, hash). Show the key to the user ONCE; store the hash."""
    key = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return key, key[:11], sha256_hex(key)
