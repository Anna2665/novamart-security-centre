from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import inspect, select

from ..db import engine, session_scope
from ..deps import Principal, get_principal, require
from ..models import Customer, DbAccessLog, Order, Payment, Product, RecordVersion
from ..security import rbac
from ..services import audit, backup, dbsec, events, state
from ..sim import rules

router = APIRouter(prefix="/db", tags=["database"])
_alerted: set[tuple] = set()


def _rows(entity: str, model, p: Principal, table: str):
    with session_scope() as db:
        out = [dbsec.verify_row(entity, r) | {"record_hash": r.record_hash, "signature": r.signature[:28] + "…"} for r in db.scalars(select(model).order_by(model.id)).all()]
    dbsec.log_access(p.username, p.role, table, "SELECT", True, len(out))
    return out


@router.get("/products")
def products(p: Principal = Depends(require("db:read"))):
    return _rows("product", Product, p, "products")


@router.get("/orders")
def orders(p: Principal = Depends(require("db:read"))):
    return _rows("order", Order, p, "orders")


@router.get("/payments")
def payments(p: Principal = Depends(require("db:read"))):
    return _rows("payment", Payment, p, "payments")


@router.get("/customers")
def customers(p: Principal = Depends(require("db:read"))):
    reveal = rbac.can(p.role, "pii:read")
    with session_scope() as db:
        out = [dbsec.customer_view(c, reveal) for c in db.scalars(select(Customer).order_by(Customer.id)).all()]
    dbsec.log_access(p.username, p.role, "customers", "SELECT", True, len(out), "PII decrypted" if reveal else "PII masked (no pii:read)")
    return {"rows": out, "pii_revealed": reveal, "role": p.role}


@router.get("/schema")
def schema(p: Principal = Depends(require("db:read"))):
    insp = inspect(engine)
    skip = {"kv", "otp_challenges", "users", "login_audit"}
    return {"dialect": engine.dialect.name, "tables": [{"name": t, "columns": [{"name": c["name"], "type": str(c["type"])} for c in insp.get_columns(t)]}
                                                         for t in insp.get_table_names() if t not in skip]}


@router.get("/integrity")
def integrity(p: Principal = Depends(require("db:read"))):
    res = dbsec.scan()
    for t in res["tampered"]:
        key = (t["entity"], t["id"], t["actual_hash"])
        if key not in _alerted:
            _alerted.add(key)
            events.emit("integrity_violation", "db", "soc", "high", "Hash + signature verification (integrity scan)", "Alert raised", "detected", "system", False, None,
                        {"entity": t["entity"], "id": t["id"], "current": t["current"], "trusted": t.get("trusted")})
    return res


class TamperIn(BaseModel):
    product_id: int = 1
    new_price: int = Field(default=1, ge=0, le=1_000_000)
    recompute_hash: bool = False


@router.post("/tamper")
def tamper(body: TamperIn, p: Principal = Depends(require("db:tamper"))):
    try:
        res = dbsec.tamper_price(body.product_id, body.new_price, f"simulated-attacker via {p.username}", body.recompute_hash)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e
    state.add_impact("manual-tamper", "db_tamper", 0, 45, 0)
    state.set_node("db", "compromised")
    state.changed()
    events.emit("db_tamper", "app", "db", "high", "None yet — run an integrity scan", "Simulated unauthorised UPDATE", "breach", "user_run", True, None,
                {"kind": "manual", "price": [res["before"]["price"], body.new_price]})
    return res


class RestoreIn(BaseModel):
    entity: str = Field(pattern=r"^(product|order|payment)$")
    id: int


@router.post("/restore")
def restore(body: RestoreIn, p: Principal = Depends(require("backup:restore"))):
    try:
        res = dbsec.restore_row(body.entity, body.id, p.username)
    except (KeyError, ValueError) as e:
        raise HTTPException(400, str(e)) from e
    if not dbsec.scan()["tampered"]:
        state.resolve_pillar("manual-tamper", "I")
        state.set_node("db", "healthy")
    state.changed()
    return res


class PriceIn(BaseModel):
    price: int = Field(ge=1, le=1_000_000)


@router.post("/products/{pid}/price")
def set_price(pid: int, body: PriceIn, p: Principal = Depends(require("db:write"))):
    return dbsec.authorised_set_price(pid, body.price, p.username)


@router.get("/access-log")
def access_log(limit: int = 60, p: Principal = Depends(require("db:read"))):
    with session_scope() as db:
        return [{"id": r.id, "ts": r.ts.replace(tzinfo=None).isoformat() + "Z", "actor": r.actor, "role": r.role, "table": r.table_name, "operation": r.operation,
                 "allowed": r.allowed, "rows": r.rows, "note": r.note} for r in db.scalars(select(DbAccessLog).order_by(DbAccessLog.id.desc()).limit(min(limit, 300))).all()]


@router.get("/versions/{entity}/{eid}")
def versions(entity: str, eid: int, p: Principal = Depends(require("db:read"))):
    with session_scope() as db:
        return [{"version": v.version, "payload": v.payload, "hash": v.record_hash, "ts": v.ts.replace(tzinfo=None).isoformat() + "Z"} for v in
                db.scalars(select(RecordVersion).where(RecordVersion.entity == entity, RecordVersion.entity_id == eid).order_by(RecordVersion.version.desc())).all()]


class SqliIn(BaseModel):
    username: str = Field(max_length=300)
    password: str = Field(default="anything", max_length=100)
    mode: str = Field(default="unsafe", pattern=r"^(unsafe|parameterised|waf)$")


@router.post("/sqli")
def sqli(body: SqliIn, p: Principal = Depends(get_principal)):
    """SQL-injection lab against an ISOLATED in-memory mock database (read-only, fictional users) — never the real database."""
    waf = rules.waf_sqli(body.username) if body.mode == "waf" else None
    if waf:
        res = {"mode": "waf", "query": "(not executed)", "params": None, "rows": [], "row_count": 0, "authenticated": False, "error": None,
               "waf": {"blocked": True, "rule": waf.id, "name": waf.name}}
    else:
        res = rules.mock_login(body.username, body.password, "unsafe" if body.mode in ("unsafe", "waf") else "parameterised")
        res["waf"] = {"blocked": False} if body.mode == "waf" else None
        res["mode"] = body.mode
    audit.log(p.username, "db.sqli_lab", body.mode, {"payload": body.username[:80], "rows": res["row_count"]})
    return res
