"""Database security: signed record versions, hash + signature verification, tamper simulation, restore, encrypted PII."""
import threading
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update

from ..db import session_scope
from ..models import KV, Customer, DbAccessLog, Order, Payment, Product, RecordVersion
from ..security import crypto, signing
from . import audit

_lock = threading.Lock()
_key_cache: dict[str, Any] = {}

ENTITIES = {
    "product": (Product, ["id", "sku", "name", "category", "price"]),  # stock changes on every sale, so it is not part of the signed record
    "order": (Order, ["id", "customer_id", "product_id", "quantity", "amount", "status"]),
    "payment": (Payment, ["id", "order_id", "amount", "method", "status", "txn_ref"]),
}


def signing_key():
    """Record-signing RSA key. Stored encrypted (AES-GCM, master-key-derived wrap key); the private key is never exposed."""
    with _lock:
        if "priv" in _key_cache:
            return _key_cache["priv"]
        with session_scope() as db:
            row = db.get(KV, "record_signing_key")
            if row:
                priv = signing.load_private(crypto.unseal(crypto.derive_key("sign-wrap"), bytes.fromhex(row.value["sealed"])))
            else:
                priv = signing.generate("RSA-PSS", 3072)
                db.add(KV(key="record_signing_key", updated_at=0.0, value={"sealed": crypto.seal(crypto.derive_key("sign-wrap"), signing.private_pem(priv)).hex(),
                                                                              "public_pem": signing.public_pem(priv)}))
        _key_cache["priv"] = priv
        return priv


def key_info() -> dict:
    priv = signing_key()
    pub = priv.public_key()
    return {"algorithm": "RSA-PSS 3072-bit, SHA-256", "fingerprint": signing.fingerprint(pub), "public_key_pem": signing.public_pem(priv),
            "private_key": "stored encrypted (AES-256-GCM) on the backend — never returned by any API"}


def payload_of(entity: str, row) -> dict:
    return {f: getattr(row, f) for f in ENTITIES[entity][1]}


def check_payload(payload: dict, stored_hash: str, signature: str) -> dict:
    """Pure integrity check used by the DB module, the scenarios and the signature lab."""
    actual = signing.record_hash(payload)
    sig_ok = signing.verify_b64(signing_key().public_key(), payload, signature) if signature else False
    return {"hash_ok": actual == stored_hash, "sig_ok": sig_ok, "stored_hash": stored_hash, "actual_hash": actual,
            "intact": actual == stored_hash and sig_ok}


def seal_row(db, entity: str, row) -> None:
    """Sign a row and append an authorised, signed version to the trusted ledger."""
    p = payload_of(entity, row)
    row.record_hash = signing.record_hash(p)
    row.signature = signing.sign_b64(signing_key(), p)
    last = db.scalar(select(func.max(RecordVersion.version)).where(RecordVersion.entity == entity, RecordVersion.entity_id == row.id)) or 0
    db.add(RecordVersion(entity=entity, entity_id=row.id, version=last + 1, payload=p, record_hash=row.record_hash,
                         signature=row.signature, ts=datetime.now(timezone.utc)))


def verify_row(entity: str, row) -> dict:
    p = payload_of(entity, row)
    chk = check_payload(p, row.record_hash, row.signature)
    return {"entity": entity, "id": row.id, "label": getattr(row, "name", None) or f"{entity} #{row.id}", "current": p, **chk,
            "status": "intact" if chk["intact"] else "TAMPERED"}


def scan() -> dict:
    out, bad = 0, []
    with session_scope() as db:
        for entity, (model, _) in ENTITIES.items():
            for row in db.scalars(select(model).order_by(model.id)).all():
                r = verify_row(entity, row)
                out += 1
                if not r["intact"]:
                    r["trusted"] = trusted_payload(db, entity, row.id)
                    bad.append(r)
    return {"total": out, "intact": out - len(bad), "tampered": bad, "scanned_at": datetime.now(timezone.utc).isoformat() + "Z"}


def trusted_payload(db, entity: str, entity_id: int) -> dict | None:
    for v in db.scalars(select(RecordVersion).where(RecordVersion.entity == entity, RecordVersion.entity_id == entity_id)
                        .order_by(RecordVersion.version.desc())).all():
        if signing.verify_b64(signing_key().public_key(), v.payload, v.signature):
            return v.payload
    return None


def tamper_price(product_id: int, new_price: int, actor: str, recompute_hash: bool = False, note: str = "UNAUTHORISED direct UPDATE") -> dict:
    """Simulated unauthorised modification: a raw UPDATE that bypasses the application and its signing logic."""
    with session_scope() as db:
        p = db.get(Product, product_id)
        if not p:
            raise KeyError("product not found")
        before = {**payload_of("product", p), "record_hash": p.record_hash, "signature_ok": verify_row("product", p)["sig_ok"]}
        values: dict[str, Any] = {"price": new_price}
        if recompute_hash:  # a smarter attacker also rewrites the stored hash — but cannot forge the RSA signature
            values["record_hash"] = signing.record_hash({**payload_of("product", p), "price": new_price})
        db.execute(update(Product).where(Product.id == product_id).values(**values))
        db.add(DbAccessLog(actor=actor, role="attacker", table_name="products", operation="UPDATE", allowed=True, rows=1, note=note))
        db.flush()
        db.refresh(p)
        after = verify_row("product", p)
    audit.log(actor, "db.tamper", f"product:{product_id}", {"price": [before["price"], new_price], "recompute_hash": recompute_hash})
    return {"before": before, "after": after, "recompute_hash": recompute_hash}


def restore_row(entity: str, entity_id: int, actor: str) -> dict:
    model, fields = ENTITIES[entity]
    with session_scope() as db:
        row = db.get(model, entity_id)
        if not row:
            raise KeyError("record not found")
        tp = trusted_payload(db, entity, entity_id)
        if tp is None:
            raise ValueError("no signed trusted version available")
        current = payload_of(entity, row)
        for f in fields:
            setattr(row, f, tp[f])
        # restore the original stored hash + signature from the verified version (signature never re-generated here)
        v = db.scalars(select(RecordVersion).where(RecordVersion.entity == entity, RecordVersion.entity_id == entity_id)
                       .order_by(RecordVersion.version.desc())).first()
        for cand in db.scalars(select(RecordVersion).where(RecordVersion.entity == entity, RecordVersion.entity_id == entity_id)
                               .order_by(RecordVersion.version.desc())).all():
            if cand.payload == tp:
                v = cand
                break
        row.record_hash, row.signature = v.record_hash, v.signature
        db.add(DbAccessLog(actor=actor, role="system", table_name=entity + "s", operation="RESTORE", allowed=True, rows=1,
                           note="restored from signed trusted version"))
        result = {"entity": entity, "id": entity_id, "restored_from": tp, "was": current, "verified": verify_row(entity, row)["intact"]}
    audit.log(actor, "db.restore", f"{entity}:{entity_id}", {"was": current, "restored": tp})
    return result


def restore_all(actor: str) -> list[dict]:
    return [restore_row(r["entity"], r["id"], actor) for r in scan()["tampered"]]


def authorised_set_price(product_id: int, price: int, actor: str) -> dict:
    with session_scope() as db:
        p = db.get(Product, product_id)
        old = p.price
        p.price, p.updated_at = price, datetime.now(timezone.utc)
        seal_row(db, "product", p)
        db.add(DbAccessLog(actor=actor, role="admin", table_name="products", operation="UPDATE", allowed=True, rows=1, note="authorised + re-signed"))
        out = verify_row("product", p)
    audit.log(actor, "db.update_price", f"product:{product_id}", {"old": old, "new": price})
    return out


# ---- PII encryption -------------------------------------------------------------------------------------------------------
def enc_field(customer_id: int, field: str, value: str) -> str:
    return crypto.seal_text("pii", value, aad=f"customer:{customer_id}:{field}")


def dec_field(customer_id: int, field: str, token: str) -> str:
    return crypto.unseal_text("pii", token, aad=f"customer:{customer_id}:{field}")


def mask(value: str, kind: str) -> str:
    if kind == "email":
        u, _, d = value.partition("@")
        return u[:1] + "•••@" + d
    if kind == "phone":
        return value[:4] + " •••••" + value[-2:]
    return value[:8] + "•••••••"


def customer_view(c: Customer, reveal: bool) -> dict:
    out = {"id": c.id, "name": c.name, "tier": c.tier}
    for f in ("email", "phone", "address"):
        token = getattr(c, f + "_enc")
        plain = dec_field(c.id, f, token)
        out[f] = plain if reveal else mask(plain, f)
        out[f + "_cipher"] = token[:44] + "…"
    out["encrypted"] = True
    return out


def log_access(actor: str, role: str, table: str, op: str, allowed: bool, rows: int, note: str = "") -> None:
    with session_scope() as db:
        db.add(DbAccessLog(actor=actor, role=role, table_name=table, operation=op, allowed=allowed, rows=rows, note=note))
