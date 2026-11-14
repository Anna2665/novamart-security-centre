import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .security import rbac, tokens

bearer = HTTPBearer(auto_error=False)


@dataclass
class Principal:
    username: str
    role: str
    jti: str | None = None


def principal_from_token(token: str) -> Principal:
    try:
        d = tokens.decode(token)
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"Invalid or expired session: {e}") from e
    return Principal(d["sub"], d.get("role", "viewer"), d.get("jti"))


def _resolve(raw: str | None) -> Principal:
    """Validate the token and re-read the role from the user store: a role claim alone is never trusted."""
    if not raw:
        raise HTTPException(401, "Authentication required")
    p = principal_from_token(raw)
    from sqlalchemy import select
    from .db import session_scope
    from .models import User
    with session_scope() as db:
        u = db.scalar(select(User).where(User.username == p.username))
        if not u:
            raise HTTPException(401, "Unknown user")
        p.role = u.role
    return p


_last_probe: dict[str, float] = {}


def _staff_only(p: Principal, path: str) -> Principal:
    if p.role != "customer":
        return p
    now = time.time()
    if now - _last_probe.get(p.username, 0) > 10:  # one event per 10 s per account, so a polling client cannot flood the feed
        _last_probe[p.username] = now
        from .services import audit, events
        audit.log(p.username, "rbac.denied", path, {"role": p.role})
        events.emit("priv_esc", "internet", "admin", "medium", "RBAC: customer role has no staff permissions", "HTTP 403 — staff API refused",
                    "blocked", "storefront", False, None, {"user": p.username, "path": path, "role": p.role})
    raise HTTPException(403, "This area is for staff only. Customer accounts cannot use it.")


def get_principal(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer), token: str | None = Query(None)) -> Principal:
    """Any signed-in STAFF member. Customer accounts are refused (and the attempt is logged as a security event)."""
    return _staff_only(_resolve(creds.credentials if creds else token), request.url.path)


def get_account(creds: HTTPAuthorizationCredentials | None = Depends(bearer), token: str | None = Query(None)) -> Principal:
    """Any signed-in account, staff or customer: for logout, own profile and own two-factor settings."""
    return _resolve(creds.credentials if creds else token)


def get_customer(p: Principal = Depends(get_account)) -> Principal:
    if p.role != "customer":
        raise HTTPException(403, "Only customer accounts can shop. Staff use the Security Centre.")
    return p


def get_optional_account(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal | None:
    """For public storefront pages that behave slightly differently when someone is signed in."""
    if not creds:
        return None
    try:
        return _resolve(creds.credentials)
    except HTTPException:
        return None


def require(perm: str):
    def dep(p: Principal = Depends(get_principal)) -> Principal:
        if not rbac.can(p.role, perm):
            from .services import audit
            audit.log(p.username, "rbac.denied", perm, {"role": p.role})
            raise HTTPException(403, f"Role '{p.role}' lacks permission '{perm}'")
        return p
    return dep


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


class SlidingLimiter:
    def __init__(self, limit: int, window: float) -> None:
        self.limit, self.window, self.hits, self.lock = limit, window, defaultdict(deque), threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            q = self.hits[key]
            while q and q[0] < now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self.lock:
            self.hits.clear()


login_limiter = SlidingLimiter(15, 60)
