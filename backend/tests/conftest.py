import os
import sys
import tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="cg-test-")
os.environ.update(DATABASE_URL=os.environ.get("TEST_DATABASE_URL", f"sqlite:///{_tmp}/test.db"), DATA_DIR=_tmp, OTP_DEV_ECHO="true", CG_ADMIN_PASSWORD="Admin#Test-2026x",
                  CG_ANALYST_PASSWORD="Analyst#Test-2026x", CG_VIEWER_PASSWORD="Viewer#Test-2026x", CG_SHOPPER_PASSWORD="Shopper#Test-2026x", SMTP_HOST="", SMTP_USER="", SMTP_PASSWORD="",
                  TELEMETRY_ENABLED="false", OTP_TTL_SECONDS="60", MAX_FAILED_LOGINS="5")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if os.environ.get("TEST_DATABASE_URL"):
    # A persistent test server keeps rows between runs, but every run makes fresh keys
    # (new DATA_DIR), so stale encrypted rows could not be read. Start from an empty schema.
    from sqlalchemy import create_engine, text
    _e = create_engine(os.environ["TEST_DATABASE_URL"])
    with _e.begin() as _c:
        _c.execute(text("DROP SCHEMA public CASCADE"))
        _c.execute(text("CREATE SCHEMA public"))
    _e.dispose()

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


def login(client, user="admin", pw=None):
    pw = pw or {"admin": "Admin#Test-2026x", "analyst": "Analyst#Test-2026x", "viewer": "Viewer#Test-2026x", "shopper": "Shopper#Test-2026x"}[user]
    from app.deps import login_limiter
    login_limiter.reset()
    r = client.post("/api/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    j = r.json()
    code = j["delivery"]["dev_otp"]
    v = client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": code})
    assert v.status_code == 200, v.text
    return {"Authorization": "Bearer " + v.json()["token"]}


_headers: dict[str, dict] = {}


def _staff(client, user):
    """Reuse one sign-in per user, but sign in again if a test (e.g. incident containment) revoked it."""
    h = _headers.get(user)
    if h is None or client.get("/api/auth/me", headers=h).status_code != 200:
        h = _headers[user] = login(client, user)
    return h


@pytest.fixture()
def admin(client):
    return _staff(client, "admin")


@pytest.fixture()
def analyst(client):
    return _staff(client, "analyst")


@pytest.fixture()
def viewer(client):
    return _staff(client, "viewer")


@pytest.fixture()
def shopper(client):
    return _staff(client, "shopper")
