import re
import secrets
import threading
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select

from ..config import settings
from ..db import session_scope
from ..deps import Principal, client_ip, get_account, get_principal, login_limiter, require
from ..models import Customer, LoginAudit, OtpChallenge, User
from ..security import otp, passwords, rbac, tokens
from ..services import audit, dbsec, email, events, state

router = APIRouter(prefix="/auth", tags=["auth"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=timezone.utc) if d is not None and d.tzinfo is None else d


def _err(status: int, msg: str, **extra) -> JSONResponse:
    return JSONResponse({"detail": msg, **extra}, status_code=status)


def _mask(addr: str) -> str:
    u, _, d = addr.partition("@")
    return (u[:2] + "•" * max(1, len(u) - 2)) + "@" + d


def _log(db, username: str, ip: str, method: str, result: str, detail: str = "") -> None:
    db.add(LoginAudit(username=username[:64], ip=ip, method=method, result=result, detail=detail[:250]))


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=200)


class CodeIn(BaseModel):
    challenge_id: str
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class ChallengeIn(BaseModel):
    challenge_id: str


def _send(ch: OtpChallenge, user: User, code: str, purpose: str = "sign-in") -> dict:
    res = email.send_otp(user.email, code, settings.otp_ttl_seconds, user.full_name or user.username, purpose)
    ch.delivery_status, ch.delivery_detail = res.status, res.detail
    out = {"status": res.status, "detail": res.detail}
    if settings.otp_dev_echo:
        out["dev_otp"] = code
        out["dev_mode"] = True
        out["detail"] = ("DEVELOPER MODE (OTP_DEV_ECHO=true): the code is shown on screen. " + ("Email also sent." if res.status == "sent" else "No email was sent — " + res.detail))
        if res.status != "sent":
            out["status"] = "dev_echo"
    return out


def _issue(db, user: User, ip: str, purpose: str) -> dict:
    """Create a one-time-code challenge for `user`, e-mail it, and describe it to the client."""
    code = otp.generate_otp()
    cid = secrets.token_urlsafe(18)
    ch = OtpChallenge(id=cid, user_id=user.id, code_hash=otp.hash_otp(code, cid), expires_at=_now() + timedelta(seconds=settings.otp_ttl_seconds))
    delivery = _send(ch, user, code, purpose)
    db.add(ch)
    _log(db, user.username, ip, "password", "otp_sent", f"delivery={delivery['status']}")
    return {"challenge_id": cid, "email_masked": _mask(user.email), "ttl": settings.otp_ttl_seconds, "max_attempts": settings.otp_max_attempts,
            "resend_cooldown": settings.otp_resend_cooldown, "methods": ["email"] + (["totp"] if user.totp_enabled else []), "delivery": delivery}


class RegisterIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)
    phone: str | None = Field(None, max_length=20)
    address: str | None = Field(None, max_length=200)


@router.post("/register")
def register(body: RegisterIn, request: Request):
    """Create a customer account. The e-mailed code then proves the address is really theirs."""
    ip = client_ip(request)
    if not login_limiter.allow(ip):
        return _err(429, "Too many attempts from this address — please slow down.")
    name = " ".join(body.full_name.split())
    if re.search(r"[<>{}\\]", name):
        return _err(422, "Name contains characters that are not allowed.")
    issues = passwords.policy_issues(body.password)
    if not state.live.defences.get("breach_check", True):
        issues = [i for i in issues if "breach" not in i]
    if issues:
        return _err(422, "Choose a stronger password: " + ", ".join(issues) + ".", issues=issues)
    addr = str(body.email).lower()
    with session_scope() as db:
        if db.scalar(select(User).where(User.username == addr)):
            return _err(409, "An account with this email already exists. Try signing in instead.")
        user = User(username=addr, email=addr, password_hash=passwords.hash_password(body.password), role="customer", full_name=name)
        db.add(user)
        db.flush()
        c = Customer(name=name, tier="standard", email_enc="", phone_enc="", address_enc="", user_id=user.id)
        db.add(c)
        db.flush()
        c.email_enc = dbsec.enc_field(c.id, "email", addr)
        c.phone_enc = dbsec.enc_field(c.id, "phone", (body.phone or "").strip())
        c.address_enc = dbsec.enc_field(c.id, "address", (body.address or "").strip())
        out = _issue(db, user, ip, "registration")
    audit.log(addr, "auth.register", "customer", {"ip": ip, "delivery": out["delivery"]["status"]})
    return out


@router.post("/login")
def login(body: LoginIn, request: Request):
    ip = client_ip(request)
    if not login_limiter.allow(ip):
        events.emit("brute_force", "internet", "auth", "medium", "Login rate limiter (15/min per IP)", "HTTP 429", "blocked", "system", False, None, {"ip": ip})
        return _err(429, "Too many login attempts from this address — slow down.")
    with session_scope() as db:
        user = db.scalar(select(User).where(User.username == body.username))
        if user and user.locked_until and _aware(user.locked_until) > _now():
            mins = max(1, int((_aware(user.locked_until) - _now()).total_seconds() // 60) + 1)
            _log(db, body.username, ip, "password", "locked", "account locked")
            return _err(423, f"Account locked after repeated failures. Try again in ~{mins} min.", locked=True)
        ok = passwords.verify_password(user.password_hash, body.password) if user else passwords.verify_password(passwords.hash_password("x"), body.password)
        if not user or not ok:
            left = None
            if user:
                user.failed_attempts += 1
                left = settings.max_failed_logins - user.failed_attempts
                if user.failed_attempts >= settings.max_failed_logins:
                    user.locked_until = _now() + timedelta(minutes=settings.lockout_minutes)
                    user.failed_attempts = 0
                    audit.log(body.username, "auth.lockout", body.username, {"ip": ip})
                    events.emit("auth_failure", "internet", "auth", "high", "Account lockout policy", "Account locked", "blocked", "system", False, None, {"user": body.username, "ip": ip})
                    threading.Thread(target=email.send_security_alert, daemon=True, args=(
                        user.email, user.full_name or user.username, "Your account was temporarily locked",
                        f"We locked your account after {settings.max_failed_logins} incorrect password attempts. It unlocks automatically after {settings.lockout_minutes} minutes.",
                        [("Locked for", f"{settings.lockout_minutes} minutes")])).start()
            _log(db, body.username, ip, "password", "failed", "bad credentials")
            audit.log(body.username, "auth.login_failed", "password", {"ip": ip})
            return _err(401, "Invalid username or password", attempts_left=max(left, 0) if left is not None else None)
        user.failed_attempts = 0
        out = _issue(db, user, ip, "sign-in")
    audit.log(body.username, "auth.password_ok", "otp_issued", {"delivery": out["delivery"]["status"], "ip": ip})
    return out


def _finish(db, ch: OtpChallenge, user: User, method: str, ip: str) -> dict:
    ch.consumed = True
    user.last_login = _now()
    _log(db, user.username, ip, method, "success", "mfa verified")
    token = tokens.issue(user.username, user.role)
    audit.log(user.username, "auth.login_success", method, {"ip": ip})
    return {"token": token, "user": {"username": user.username, "full_name": user.full_name or user.username, "role": user.role, "permissions": sorted(rbac.PERMISSIONS[user.role])},
            "expires_minutes": settings.session_minutes}


def _check_challenge(db, cid: str):
    ch = db.get(OtpChallenge, cid)
    if not ch or ch.consumed:
        return None, None, _err(400, "This sign-in attempt is no longer valid. Please log in again.", restart=True)
    user = db.get(User, ch.user_id)
    if _aware(ch.expires_at) < _now():
        return ch, user, _err(410, "The code has expired. Request a new one.", expired=True)
    if ch.attempts >= settings.otp_max_attempts:
        ch.consumed = True
        return ch, user, _err(429, "Too many wrong codes. Please log in again.", restart=True)
    return ch, user, None


def _wrong(db, ch, user, ip, method):
    ch.attempts += 1
    left = settings.otp_max_attempts - ch.attempts
    _log(db, user.username, ip, method, "failed", f"wrong code ({ch.attempts}/{settings.otp_max_attempts})")
    audit.log(user.username, "auth.mfa_failed", method, {"ip": ip, "attempts": ch.attempts})
    events.emit("auth_failure", "internet", "auth", "medium", f"{method.upper()} verification", "Wrong code rejected", "blocked", "system", False, None, {"user": user.username})
    if left <= 0:
        ch.consumed = True
        return _err(429, "Wrong code — no attempts left. Please log in again.", attempts_left=0, restart=True)
    return _err(401, f"Wrong code. {left} attempt{'s' if left != 1 else ''} left.", attempts_left=left)


@router.post("/otp/verify")
def verify_otp(body: CodeIn, request: Request):
    ip = client_ip(request)
    with session_scope() as db:
        ch, user, err = _check_challenge(db, body.challenge_id)
        if err:
            return err
        if not otp.check_otp(body.code, ch.id, ch.code_hash):
            return _wrong(db, ch, user, ip, "email_otp")
        return _finish(db, ch, user, "email_otp", ip)


@router.post("/totp/verify")
def verify_totp(body: CodeIn, request: Request):
    ip = client_ip(request)
    with session_scope() as db:
        ch, user, err = _check_challenge(db, body.challenge_id)
        if err:
            return err
        if not user.totp_enabled or not user.totp_secret_enc:
            return _err(400, "Authenticator app is not enrolled for this account.")
        if not otp.verify_totp(otp.open_secret(user.totp_secret_enc, user.username), body.code):
            return _wrong(db, ch, user, ip, "totp")
        return _finish(db, ch, user, "totp", ip)


@router.post("/otp/resend")
def resend(body: ChallengeIn, request: Request):
    with session_scope() as db:
        ch = db.get(OtpChallenge, body.challenge_id)
        if not ch or ch.consumed:
            return _err(400, "This sign-in attempt is no longer valid. Please log in again.", restart=True)
        wait = settings.otp_resend_cooldown - (_now() - _aware(ch.last_sent_at)).total_seconds()
        if wait > 0:
            return _err(429, f"Please wait {int(wait) + 1}s before requesting another code.", retry_after=int(wait) + 1)
        if ch.resend_count >= 5:
            ch.consumed = True
            return _err(429, "Resend limit reached. Please log in again.", restart=True)
        user = db.get(User, ch.user_id)
        code = otp.generate_otp()  # a fresh code; the previous one stops working
        ch.code_hash, ch.expires_at, ch.attempts, ch.last_sent_at = otp.hash_otp(code, ch.id), _now() + timedelta(seconds=settings.otp_ttl_seconds), 0, _now()
        ch.resend_count += 1
        delivery = _send(ch, user, code)
    audit.log(user.username, "auth.otp_resend", "otp", {"delivery": delivery["status"]})
    return {"ttl": settings.otp_ttl_seconds, "delivery": delivery, "email_masked": _mask(user.email)}


@router.post("/logout")
def logout(request: Request, p: Principal = Depends(get_account)):
    auth = request.headers.get("authorization", "")
    tokens.revoke(auth.removeprefix("Bearer ").strip())
    audit.log(p.username, "auth.logout", "", {})
    return {"ok": True}


@router.get("/me")
def me(p: Principal = Depends(get_account)):
    with session_scope() as db:
        u = db.scalar(select(User).where(User.username == p.username))
        return {"username": u.username, "full_name": u.full_name or u.username, "role": u.role, "email_masked": _mask(u.email), "totp_enabled": u.totp_enabled,
                "permissions": sorted(rbac.PERMISSIONS[u.role]), "last_login": u.last_login.isoformat() + "Z" if u.last_login else None}


@router.get("/audit")
def login_audit(limit: int = 60, p: Principal = Depends(get_principal)):
    with session_scope() as db:
        q = select(LoginAudit).order_by(LoginAudit.id.desc()).limit(min(limit, 300))
        if not rbac.can(p.role, "users:manage"):
            q = select(LoginAudit).where(LoginAudit.username == p.username).order_by(LoginAudit.id.desc()).limit(min(limit, 300))
        return [{"id": r.id, "ts": r.ts.replace(tzinfo=None).isoformat() + "Z", "username": r.username, "ip": r.ip, "method": r.method, "result": r.result, "detail": r.detail}
                for r in db.scalars(q).all()]


@router.get("/users")
def users(p: Principal = Depends(require("users:manage"))):
    with session_scope() as db:
        return [{"username": u.username, "role": u.role, "email_masked": _mask(u.email), "totp_enabled": u.totp_enabled, "failed_attempts": u.failed_attempts,
                 "locked": bool(u.locked_until and _aware(u.locked_until) > _now()),
                 "locked_until": u.locked_until.replace(tzinfo=None).isoformat() + "Z" if u.locked_until else None,
                 "last_login": u.last_login.replace(tzinfo=None).isoformat() + "Z" if u.last_login else None,
                 "hash_algorithm": u.password_hash.split("$")[1] if u.password_hash.startswith("$argon2") else "?"} for u in db.scalars(select(User)).all()]


@router.post("/users/{username}/unlock")
def unlock(username: str, p: Principal = Depends(require("users:manage"))):
    with session_scope() as db:
        u = db.scalar(select(User).where(User.username == username))
        if not u:
            return _err(404, "No such user")
        u.locked_until, u.failed_attempts = None, 0
    audit.log(p.username, "auth.unlock", username, {})
    return {"ok": True}


class EnrollOut(BaseModel):
    secret: str
    uri: str


@router.post("/totp/enroll")
def totp_enroll(p: Principal = Depends(get_account)):
    with session_scope() as db:
        u = db.scalar(select(User).where(User.username == p.username))
        secret = otp.new_totp_secret()
        u.totp_secret_enc, u.totp_enabled = otp.seal_secret(secret, u.username), False
    audit.log(p.username, "auth.totp_enroll_start", "", {})
    return {"secret": secret, "uri": otp.totp_uri(secret, p.username)}


class TotpCode(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


@router.post("/totp/confirm")
def totp_confirm(body: TotpCode, p: Principal = Depends(get_account)):
    with session_scope() as db:
        u = db.scalar(select(User).where(User.username == p.username))
        if not u.totp_secret_enc or not otp.verify_totp(otp.open_secret(u.totp_secret_enc, u.username), body.code):
            return _err(400, "Code does not match — check the authenticator app and the phone clock.")
        u.totp_enabled = True
    audit.log(p.username, "auth.totp_enabled", "", {})
    return {"ok": True}


@router.post("/totp/disable")
def totp_disable(body: TotpCode, p: Principal = Depends(get_account)):
    with session_scope() as db:
        u = db.scalar(select(User).where(User.username == p.username))
        if not u.totp_enabled or not otp.verify_totp(otp.open_secret(u.totp_secret_enc, u.username), body.code):
            return _err(400, "Code does not match.")
        u.totp_enabled, u.totp_secret_enc = False, None
    audit.log(p.username, "auth.totp_disabled", "", {})
    return {"ok": True}


@router.get("/rbac")
def rbac_matrix(p: Principal = Depends(get_principal)):
    return {"roles": list(rbac.PERMISSIONS), "permissions": rbac.ALL_PERMISSIONS, "descriptions": rbac.DESCRIPTIONS,
            "matrix": {r: sorted(v) for r, v in rbac.PERMISSIONS.items()}}


class PermCheck(BaseModel):
    role: str
    permission: str


@router.post("/check-permission")
def check_permission(body: PermCheck, p: Principal = Depends(get_principal)):
    allowed = rbac.can(body.role, body.permission)
    return {"role": body.role, "permission": body.permission, "allowed": allowed,
            "reason": "granted by the role's permission set" if allowed else "not in the role's permission set → server answers 403"}


@router.get("/policy")
def policy(p: Principal = Depends(get_principal)):
    h = passwords.hasher
    return {"password_hash": {"algorithm": "Argon2id", "time_cost": h.time_cost, "memory_kib": h.memory_cost, "parallelism": h.parallelism},
            "password_rules": ["≥ 12 characters", "upper + lower case", "digit and symbol", "not in breach corpus"],
            "otp": {"digits": 6, "ttl_seconds": settings.otp_ttl_seconds, "max_attempts": settings.otp_max_attempts, "resend_cooldown": settings.otp_resend_cooldown,
                    "storage": "HMAC-SHA256 with server pepper (the code itself is never stored)"},
            "lockout": {"max_failed": settings.max_failed_logins, "minutes": settings.lockout_minutes},
            "session": {"minutes": settings.session_minutes, "alg": "HS256 JWT, role re-read from the user store on every request"}}
