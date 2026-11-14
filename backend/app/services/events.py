"""Security event feed + metrics. Every event is tagged simulated/real and by origin."""
import secrets
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from ..bus import bus
from ..db import session_scope
from ..models import SecurityEvent

ATTACK_LABELS = {
    "sqli": "SQL Injection", "db_tamper": "Database Tampering", "xss": "Cross-Site Scripting", "csrf": "CSRF",
    "brute_force": "Brute Force", "cred_stuffing": "Credential Stuffing", "phishing": "Phishing", "ddos": "DDoS",
    "ransomware": "Ransomware", "priv_esc": "Privilege Escalation", "exfiltration": "Data Exfiltration", "mitm": "Man-in-the-Middle",
    "integrity_violation": "Integrity Violation", "auth_failure": "Authentication Failure", "port_scan": "Port Scan",
}
PILLARS = {"sqli": "CI", "db_tamper": "I", "xss": "CI", "csrf": "IC", "brute_force": "C", "cred_stuffing": "C", "phishing": "C",
           "ddos": "A", "ransomware": "AI", "priv_esc": "CI", "exfiltration": "C", "mitm": "CI", "integrity_violation": "I",
           "auth_failure": "C", "port_scan": "C"}


def _naive(ts: datetime) -> datetime:
    return ts.astimezone(timezone.utc).replace(tzinfo=None) if ts.tzinfo else ts


def to_dict(e: SecurityEvent) -> dict[str, Any]:
    return {"id": e.id, "event_id": e.event_id, "ts": _naive(e.ts).isoformat() + "Z", "attack_type": e.attack_type,
            "label": ATTACK_LABELS.get(e.attack_type, e.attack_type), "source_node": e.source_node, "target_node": e.target_node,
            "severity": e.severity, "detection": e.detection, "action": e.action, "result": e.result, "origin": e.origin,
            "simulated": e.simulated, "run_id": e.run_id, "details": e.details, "pillars": PILLARS.get(e.attack_type, "")}


def emit(attack_type: str, source: str, target: str, severity: str, detection: str, action: str, result: str,
         origin: str = "user_run", simulated: bool = True, run_id: str | None = None, details: dict | None = None,
         ts: datetime | None = None, publish: bool = True) -> dict:
    when = _naive(ts or datetime.now(timezone.utc))
    eid = f"EVT-{when:%y%m%d}-{secrets.token_hex(3).upper()}"
    with session_scope() as db:
        e = SecurityEvent(event_id=eid, ts=when, attack_type=attack_type, source_node=source, target_node=target, severity=severity,
                          detection=detection, action=action, result=result, origin=origin, simulated=simulated, run_id=run_id,
                          details=details or {})
        db.add(e)
        db.flush()
        out = to_dict(e)
    if publish:
        bus.publish("event", out)
    return out


def recent(limit: int = 100, **filters: Any) -> list[dict]:
    with session_scope() as db:
        q = select(SecurityEvent).order_by(SecurityEvent.id.desc())
        for k in ("attack_type", "severity", "result", "origin"):
            if filters.get(k):
                q = q.where(getattr(SecurityEvent, k) == filters[k])
        return [to_dict(e) for e in db.scalars(q.limit(limit)).all()]


def _is_guard(e: SecurityEvent) -> bool:
    """Per-defence log lines emitted during a run; they belong in the feed but are not separate attacks."""
    return (e.details or {}).get("kind") == "guard"


def counters() -> dict[str, Any]:
    with session_scope() as db:
        rows = db.scalars(select(SecurityEvent)).all()
    attacks = [e for e in rows if e.attack_type in ATTACK_LABELS and e.origin != "system" and not _is_guard(e)]
    res = Counter(e.result for e in attacks)
    return {"total_attacks": len(attacks), "blocked": res.get("blocked", 0), "contained": res.get("contained", 0),
            "breaches": res.get("breach", 0), "critical_alerts": sum(1 for e in rows if e.severity == "critical"),
            "simulated_events": sum(1 for e in rows if e.simulated), "real_events": sum(1 for e in rows if not e.simulated),
            "by_origin": dict(Counter(e.origin for e in rows))}


def distribution() -> list[dict]:
    with session_scope() as db:
        rows = db.scalars(select(SecurityEvent)).all()
    c = Counter(e.attack_type for e in rows if e.attack_type in ATTACK_LABELS and not _is_guard(e))
    return [{"type": k, "label": ATTACK_LABELS[k], "count": v} for k, v in c.most_common()]


def trend(hours: int = 48, bucket: int = 3) -> list[dict]:
    end = datetime.now(timezone.utc).replace(tzinfo=None)
    start = end - timedelta(hours=hours)
    with session_scope() as db:
        rows = db.scalars(select(SecurityEvent).where(SecurityEvent.ts >= start)).all()
    n = hours // bucket
    buckets = [{"ts": (start + timedelta(hours=bucket * i)).isoformat() + "Z", "blocked": 0, "contained": 0, "breach": 0, "other": 0} for i in range(n + 1)]
    for e in (r for r in rows if not _is_guard(r)):
        idx = min(int((e.ts - start).total_seconds() // (3600 * bucket)), n)
        key = e.result if e.result in ("blocked", "contained", "breach") else "other"
        buckets[idx][key] += 1
    return buckets
