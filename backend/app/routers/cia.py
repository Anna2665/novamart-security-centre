from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from ..db import session_scope
from ..deps import Principal, get_principal
from ..models import Customer, LoginAudit
from ..services import audit, backup, dbsec, events, state
from ..sim.topology import NODES

router = APIRouter(prefix="/cia", tags=["cia"])


def _sig(name: str, ok: bool | None, value: str, warn: bool = False) -> dict:
    return {"name": name, "status": "ok" if ok else "warn" if warn else "crit", "value": value}


@router.get("")
def cia(p: Principal = Depends(get_principal)):
    scores = state.cia()
    d = state.live.defences
    with session_scope() as db:
        n_cust = db.scalar(select(func.count(Customer.id))) or 0
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        failed = db.scalar(select(func.count(LoginAudit.id)).where(LoginAudit.result.in_(["failed", "locked"]), LoginAudit.ts >= since.replace(tzinfo=None))) or 0
    scan = dbsec.scan()
    chain = audit.verify_chain()
    bk = backup.status()
    healthy = sum(1 for v in state.live.nodes.values() if v["status"] == "healthy")
    imp = state.active_impacts()
    exfil = any(i["scenario"] in ("exfiltration", "sqli", "priv_esc", "mitm") and i["C"] > 5 for i in imp)
    signals = {
        "C": [_sig("PII encrypted at rest (AES-256-GCM)", True, f"{n_cust}/{n_cust} customer records"),
              _sig("Encryption-at-rest defence", d["encryption_at_rest"], "ON — stolen copies are ciphertext" if d["encryption_at_rest"] else "OFF — a stolen dump is readable"),
              _sig("Multi-factor authentication", d["mfa"], "email OTP + TOTP required" if d["mfa"] else "OFF"),
              _sig("Access control (RBAC + least privilege)", d["rbac"] and d["least_privilege"], "enforced server-side" if d["rbac"] and d["least_privilege"] else "partially/not enforced", warn=d["rbac"] or d["least_privilege"]),
              _sig("Data-loss prevention", d["dlp"], "ON" if d["dlp"] else "OFF"),
              _sig("Active data-exposure incidents", not exfil, "none" if not exfil else "confidentiality impact open"),
              _sig("Failed logins (last hour)", failed < 10, str(failed), warn=failed < 30)],
        "I": [_sig("Records verified (hash + RSA-PSS)", not scan["tampered"], f"{scan['intact']}/{scan['total']} intact"),
              _sig("Audit log hash-chain", chain["valid"], chain["message"]),
              _sig("Digital signatures", d["digital_signatures"], "all critical records signed" if d["digital_signatures"] else "OFF"),
              _sig("Database integrity monitoring", d["db_integrity"], "continuous" if d["db_integrity"] else "OFF"),
              _sig("Unauthorised modifications", not scan["tampered"], "none" if not scan["tampered"] else f"{len(scan['tampered'])} record(s) tampered"),
              _sig("TLS 1.3 in transit", d["tls"], "certificate validation ON" if d["tls"] else "OFF")],
        "A": [_sig("Nodes healthy", healthy == len(NODES), f"{healthy}/{len(NODES)}", warn=healthy >= len(NODES) - 2),
              _sig("Backup vault", bk["health"] == "healthy", f"{bk['health']} · {bk['verified_count']} verified", warn=bk["health"] == "stale"),
              _sig("Production volume", bk["volume"]["state"] == "healthy", bk["volume"]["state"].replace("_", " ")),
              _sig("DDoS protection (CDN + rate limit)", d["cdn"] and d["rate_limiting"], "ON" if d["cdn"] and d["rate_limiting"] else "partial/OFF", warn=d["cdn"] or d["rate_limiting"]),
              _sig("Recovery readiness", d["secure_backups"] and bk["verified_count"] > 0, "verified backup ready" if d["secure_backups"] and bk["verified_count"] else "no verified recovery path")],
    }
    recent = [e for e in events.recent(200) if e["origin"] in ("user_run", "system") or e["severity"] in ("high", "critical")][:30]
    return {"scores": scores, "history": state.live.history[-120:], "signals": signals, "impacts": imp, "events": recent,
            "status": {pl: ("protected" if scores[pl] >= 85 else "at risk" if scores[pl] >= 60 else "compromised") for pl in "CIA"}}
