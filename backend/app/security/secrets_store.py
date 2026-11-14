"""Secret bootstrap: environment variables win; otherwise random secrets are generated once into data/secrets.json (0600)."""
import base64
import json
import os
import secrets as _s
from pathlib import Path

from ..config import settings

_FILE = Path(settings.data_dir) / "secrets.json"
_cache: dict | None = None


def _load() -> dict:
    global _cache
    if _cache is None:
        if _FILE.exists():
            _cache = json.loads(_FILE.read_text())
        else:
            _cache = {}
    return _cache


def _persist() -> None:
    _FILE.write_text(json.dumps(_cache))
    try:
        os.chmod(_FILE, 0o600)
    except OSError:
        pass


def _get(name: str, env_value: str | None, factory) -> str:
    if env_value:
        return env_value
    data = _load()
    if name not in data:
        data[name] = factory()
        _persist()
    return data[name]


def master_key() -> bytes:
    raw = _get("master_key", settings.cg_master_key, lambda: base64.b64encode(os.urandom(32)).decode())
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise RuntimeError("CG_MASTER_KEY must be base64 of exactly 32 bytes")
    return key


def jwt_secret() -> str:
    return _get("jwt_secret", settings.jwt_secret, lambda: _s.token_urlsafe(48))


def otp_pepper() -> bytes:
    return _get("otp_pepper", settings.otp_pepper, lambda: _s.token_urlsafe(32)).encode()
