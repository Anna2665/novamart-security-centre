import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from ..config import settings
from .secrets_store import jwt_secret

_revoked: set[str] = set()
_lock = threading.Lock()


def issue(username: str, role: str, minutes: int | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": username, "role": role, "jti": secrets.token_hex(8), "iat": now,
               "exp": now + timedelta(minutes=minutes or settings.session_minutes)}
    return jwt.encode(payload, jwt_secret(), algorithm="HS256")


def decode(token: str) -> dict[str, Any]:
    """Signature is always verified (HS256 only, no 'none' algorithm); revoked tokens are rejected."""
    data = jwt.decode(token, jwt_secret(), algorithms=["HS256"], options={"require": ["exp", "sub"]})
    with _lock:
        if data.get("jti") in _revoked:
            raise jwt.InvalidTokenError("token revoked")
        if _epoch and data.get("iat", 0) < int(_epoch.timestamp()) and data.get("jti") not in _exempt:
            raise jwt.InvalidTokenError("session revoked by security response")
    return data


def revoke(token: str) -> None:
    try:
        data = jwt.decode(token, jwt_secret(), algorithms=["HS256"])
        with _lock:
            _revoked.add(data.get("jti", ""))
    except jwt.PyJWTError:
        pass


_epoch: datetime | None = None


_exempt: set[str] = set()


def revoke_all_sessions(keep_jti: str | None = None) -> None:
    """Containment action: every token issued before now is rejected, except the responder's own session."""
    global _epoch
    with _lock:
        _epoch = datetime.now(timezone.utc)
        _exempt.clear()
        if keep_jti:
            _exempt.add(keep_jti)
