from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from ..db import session_scope
from ..deps import Principal, get_principal, require
from ..models import AuditLog
from ..services import audit, events, state
from ..sim.topology import NODES

router = APIRouter(tags=["events"])


@router.get("/events")
def feed(limit: int = 100, attack_type: str | None = None, severity: str | None = None, result: str | None = None, origin: str | None = None,
         p: Principal = Depends(get_principal)):
    return events.recent(min(limit, 500), attack_type=attack_type, severity=severity, result=result, origin=origin)


@router.get("/metrics")
def metrics(p: Principal = Depends(get_principal)):
    c = events.counters()
    snap = state.snapshot()
    from ..services import backup, dbsec
    scan = dbsec.scan()
    nodes = snap["nodes"]
    protected = sum(1 for v in nodes.values() if v["status"] in ("healthy", "protected"))
    from ..db import session_scope as ss
    from ..models import Customer, User
    with ss() as db:
        users = db.scalars(select(User)).all()
        n_cust = len(db.scalars(select(Customer)).all())
    bk = backup.status()
    return {"counters": c, "distribution": events.distribution(), "trend": events.trend(48, 3), "cia": snap["cia"], "nodes": nodes, "node_counts": snap["node_counts"],
            "protected_nodes": protected, "total_nodes": len(NODES), "mode": snap["mode"],
            "encryption_coverage": {"percent": round((3 + 2 * snap["defences"]["encryption_at_rest"]) / 5 * 100),
                                    "detail": f"{n_cust} customer records, TOTP secrets and backups: AES-256-GCM (always); cloud exports + transit: with defence ON",
                                    "defence_on": snap["defences"]["encryption_at_rest"]},
            "integrity": {"intact": scan["intact"], "total": scan["total"], "tampered": len(scan["tampered"])},
            "mfa": {"users": len(users), "totp_enrolled": sum(u.totp_enabled for u in users), "email_otp_enforced": snap["defences"]["mfa"]},
            "backup": {"health": bk["health"], "verified": bk["verified_count"], "last": bk["last_backup"]},
            "defences_on": sum(snap["defences"].values()), "defences_total": len(snap["defences"]), "running": snap["running"]}


@router.get("/audit")
def audit_log(limit: int = 100, action: str | None = None, actor: str | None = None, q: str | None = None, p: Principal = Depends(require("audit:read"))):
    with session_scope() as db:
        stmt = select(AuditLog).order_by(AuditLog.id.desc())
        if action:
            stmt = stmt.where(AuditLog.action.like(f"{action}%"))
        if actor:
            stmt = stmt.where(AuditLog.actor == actor)
        rows = [audit.to_dict(r) for r in db.scalars(stmt.limit(min(limit, 1000))).all()]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in (r["action"] + r["actor"] + r["target"] + str(r["detail"])).lower()]
    return rows


@router.get("/audit/verify")
def audit_verify(p: Principal = Depends(require("audit:read"))):
    return audit.verify_chain()
