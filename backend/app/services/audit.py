"""Append-only, SHA-256 hash-chained audit log. Editing or deleting any row breaks every later hash."""
import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from ..bus import bus
from ..db import session_scope
from ..models import AuditLog

_lock = threading.Lock()
GENESIS = "0" * 64


def _naive(ts: datetime) -> datetime:
    return ts.astimezone(timezone.utc).replace(tzinfo=None) if ts.tzinfo else ts


def _digest(prev: str, ts: datetime, actor: str, action: str, target: str, detail: Any) -> str:
    body = json.dumps([prev, _naive(ts).isoformat(timespec="microseconds"), actor, action, target, detail],
                      sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def log(actor: str, action: str, target: str = "", detail: dict | None = None) -> dict:
    detail = json.loads(json.dumps(detail or {}, default=str))
    with _lock, session_scope() as db:
        last = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).first()
        prev = last.entry_hash if last else GENESIS
        ts = _naive(datetime.now(timezone.utc))
        row = AuditLog(ts=ts, actor=actor, action=action, target=target, detail=detail, prev_hash=prev,
                       entry_hash=_digest(prev, ts, actor, action, target, detail))
        db.add(row)
        db.flush()
        out = to_dict(row)
    bus.publish("audit", out)
    return out


def to_dict(r: AuditLog) -> dict:
    return {"id": r.id, "ts": _naive(r.ts).isoformat() + "Z", "actor": r.actor, "action": r.action, "target": r.target,
            "detail": r.detail, "prev_hash": r.prev_hash, "entry_hash": r.entry_hash}


def verify_chain() -> dict:
    with session_scope() as db:
        rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
        prev = GENESIS
        for r in rows:
            ok = r.prev_hash == prev and r.entry_hash == _digest(prev, r.ts, r.actor, r.action, r.target, r.detail)
            if not ok:
                return {"valid": False, "checked": r.id, "total": len(rows), "first_bad_id": r.id,
                        "message": f"Chain broken at entry #{r.id}: stored hash does not match recomputed hash (record modified or removed)."}
            prev = r.entry_hash
        return {"valid": True, "checked": len(rows), "total": len(rows), "first_bad_id": None, "head": prev,
                "message": f"All {len(rows)} entries verified — chain intact."}


def count() -> int:
    with session_scope() as db:
        return db.scalar(select(func.count(AuditLog.id))) or 0
