import hashlib
import hmac
import secrets

import pyotp

from . import crypto
from .secrets_store import otp_pepper


def generate_otp() -> str:
    """Cryptographically secure six-digit code (uses the OS CSPRNG via `secrets`)."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(code: str, challenge_id: str) -> str:
    return hmac.new(otp_pepper(), f"{challenge_id}:{code}".encode(), hashlib.sha256).hexdigest()


def check_otp(code: str, challenge_id: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_otp(code, challenge_id), stored_hash)


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="CyberGuard X")


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def seal_secret(secret: str, username: str) -> str:
    return crypto.seal_text("totp", secret, aad=username)


def open_secret(token: str, username: str) -> str:
    return crypto.unseal_text("totp", token, aad=username)
