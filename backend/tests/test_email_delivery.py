"""Proves the OTP e-mail path against a real SMTP server (a local aiosmtpd instance): the code is actually transmitted, and failures are reported honestly."""
import re
import socket

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

from app.config import settings
from app.services import email


class Inbox:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(envelope)
        return "250 OK"


def _auth(server, session, envelope, mechanism, auth_data):
    ok = isinstance(auth_data, LoginPassword) and auth_data.login == b"sender@test.example" and auth_data.password == b"app-password"
    return AuthResult(success=ok)


@pytest.fixture()
def smtp(monkeypatch):
    inbox = Inbox()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    ctl = Controller(inbox, hostname="127.0.0.1", port=port, authenticator=_auth, auth_required=True, auth_require_tls=False)
    ctl.start()
    for k, v in dict(smtp_host="127.0.0.1", smtp_port=port, smtp_user="sender@test.example", smtp_password="app-password",
                     smtp_security="none", smtp_from="CyberGuard X <sender@test.example>", otp_dev_echo=False).items():
        monkeypatch.setattr(settings, k, v)
    yield inbox
    ctl.stop()


def _code_from(envelope) -> str:
    body = envelope.content.decode(errors="replace")
    m = re.search(r"verification code is: (\d{6})", body.replace("=\r\n", ""))
    assert m, body[:400]
    return m.group(1)


def test_otp_email_is_really_delivered_and_contains_the_code(smtp):
    r = email.send_otp(settings.demo_email, "482913", 60, "admin")
    assert r.status == "sent"
    assert len(smtp.messages) == 1
    msg = smtp.messages[0]
    assert msg.rcpt_tos == [settings.demo_email]
    assert "482913" in msg.content.decode(errors="replace")


def test_login_emails_a_code_that_signs_you_in_and_never_echoes_it(client, smtp):
    from app.deps import login_limiter
    login_limiter.reset()
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Admin#Test-2026x"})
    j = r.json()
    assert j["delivery"]["status"] == "sent" and "dev_otp" not in j["delivery"] and "dev_mode" not in j["delivery"]
    code = _code_from(smtp.messages[-1])
    assert smtp.messages[-1].rcpt_tos == [settings.demo_email]
    v = client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": code})
    assert v.status_code == 200 and v.json()["token"]


def test_resend_sends_a_new_email_and_kills_the_old_code(client, smtp):
    from datetime import datetime, timedelta, timezone
    from app.db import session_scope
    from app.deps import login_limiter
    from app.models import OtpChallenge
    login_limiter.reset()
    j = client.post("/api/auth/login", json={"username": "analyst", "password": "Analyst#Test-2026x"}).json()
    first = _code_from(smtp.messages[-1])
    with session_scope() as db:
        db.get(OtpChallenge, j["challenge_id"]).last_sent_at = datetime.now(timezone.utc) - timedelta(seconds=settings.otp_resend_cooldown + 1)
    assert client.post("/api/auth/otp/resend", json={"challenge_id": j["challenge_id"]}).json()["delivery"]["status"] == "sent"
    second = _code_from(smtp.messages[-1])
    assert len(smtp.messages) == 2
    if first != second:
        assert client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": first}).status_code == 401
    assert client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": second}).status_code == 200


def test_rejected_smtp_login_is_reported_as_failed_not_sent(smtp, monkeypatch):
    import smtplib

    def refuse(self, user, password, **kw):
        raise smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")
    monkeypatch.setattr(smtplib.SMTP, "login", refuse)
    r = email.send_otp(settings.demo_email, "111111", 60, "admin")
    assert r.status == "failed" and "App Password" in r.detail
    assert smtp.messages == []


def test_unreachable_server_is_reported_as_failed(monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    for k, v in dict(smtp_host="127.0.0.1", smtp_port=port, smtp_user="a@b.example", smtp_password="x", smtp_security="none").items():
        monkeypatch.setattr(settings, k, v)
    r = email.send_otp(settings.demo_email, "111111", 60, "admin")
    assert r.status == "failed"


def test_login_reports_failed_delivery_instead_of_pretending(client, monkeypatch):
    from app.deps import login_limiter
    for k, v in dict(smtp_host="127.0.0.1", smtp_port=1, smtp_user="a@b.example", smtp_password="x", smtp_security="none", otp_dev_echo=False).items():
        monkeypatch.setattr(settings, k, v)
    login_limiter.reset()
    j = client.post("/api/auth/login", json={"username": "viewer", "password": "Viewer#Test-2026x"}).json()
    assert j["delivery"]["status"] == "failed" and "dev_otp" not in j["delivery"]


def test_not_configured_is_reported_honestly(client, monkeypatch):
    from app.deps import login_limiter
    for k, v in dict(smtp_host=None, smtp_user=None, smtp_password=None, otp_dev_echo=False).items():
        monkeypatch.setattr(settings, k, v)
    login_limiter.reset()
    j = client.post("/api/auth/login", json={"username": "viewer", "password": "Viewer#Test-2026x"}).json()
    assert j["delivery"]["status"] == "not_configured" and "dev_otp" not in j["delivery"]


# ---- HTTPS provider (Resend): used on hosts that block outgoing SMTP ports -------------------------------
class _Resp:
    def __init__(self, body: bytes):
        self._b = body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_https_provider_posts_to_resend_and_reports_sent(monkeypatch):
    import json
    seen = {}

    def fake(req, timeout=0):
        seen.update(url=req.full_url, auth=req.get_header("Authorization"), body=json.loads(req.data))
        return _Resp(b'{"id": "abc123"}')

    monkeypatch.setattr(settings, "resend_api_key", "re_test_key")
    monkeypatch.setattr(settings, "smtp_host", None)
    monkeypatch.setattr(email.urllib.request, "urlopen", fake)
    r = email.send_otp("anna@example.com", "482913", 60, "admin")
    assert r.status == "sent" and "abc123" in r.detail
    assert seen["url"] == "https://api.resend.com/emails"
    assert seen["auth"] == "Bearer re_test_key"
    assert seen["body"]["to"] == ["anna@example.com"] and "482913" in seen["body"]["html"] and "482913" in seen["body"]["text"]


def test_https_provider_reports_a_rejection_honestly(monkeypatch):
    import io
    import urllib.error

    def fake(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(b'{"message": "You can only send testing emails to your own email address"}'))

    monkeypatch.setattr(settings, "resend_api_key", "re_test_key")
    monkeypatch.setattr(email.urllib.request, "urlopen", fake)
    r = email.send_otp("someone@example.com", "111111", 60, "customer")
    assert r.status == "failed" and "403" in r.detail and "only send testing emails" in r.detail
