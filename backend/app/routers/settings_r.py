from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..config import settings
from ..db import engine
from ..deps import Principal, get_principal, require
from ..services import audit, email, seed

router = APIRouter(prefix="/settings", tags=["settings"])


def _mask(s: str | None) -> str:
    if not s:
        return "—"
    u, _, d = s.partition("@")
    return (u[:2] + "•••") + ("@" + d if d else "")


@router.get("")
def get(p: Principal = Depends(get_principal)):
    return {"smtp": {"configured": settings.email_configured, "provider": "Resend (HTTPS)" if settings.resend_api_key else "SMTP", "host": settings.smtp_host or ("api.resend.com" if settings.resend_api_key else None), "port": settings.smtp_port, "security": settings.smtp_security,
                     "user": _mask(settings.smtp_user), "password": "set (hidden)" if settings.smtp_password else "not set"},
            "recipient": _mask(settings.demo_email), "otp": {"ttl": settings.otp_ttl_seconds, "max_attempts": settings.otp_max_attempts, "dev_echo": settings.otp_dev_echo},
            "telemetry_enabled": settings.telemetry_enabled, "session_minutes": settings.session_minutes, "database": engine.dialect.name, "version": "1.0.0"}


class SettingsIn(BaseModel):
    telemetry_enabled: bool


@router.put("")
def update(body: SettingsIn, p: Principal = Depends(require("settings:manage"))):
    settings.telemetry_enabled = body.telemetry_enabled
    audit.log(p.username, "settings.update", "telemetry", {"enabled": body.telemetry_enabled})
    return {"telemetry_enabled": settings.telemetry_enabled}


@router.post("/test-email")
def test_email(p: Principal = Depends(require("settings:manage"))):
    r = email.send_test(settings.demo_email)
    audit.log(p.username, "settings.test_email", "smtp", {"status": r.status})
    return {"status": r.status, "detail": r.detail}


class ResetIn(BaseModel):
    confirm: bool


@router.post("/reset-all")
def reset_all(body: ResetIn, p: Principal = Depends(require("system:reset"))):
    if not body.confirm:
        raise HTTPException(400, "confirmation required")
    seed.reset_data()
    audit.log(p.username, "system.reset", "simulation", {})
    return {"ok": True}
