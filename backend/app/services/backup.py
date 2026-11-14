"""Isolated backup vault: encrypted (AES-256-GCM), hashed, signed snapshots + the in-memory production volume used by ransomware demos."""
import base64
import hashlib
import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from ..db import session_scope
from ..models import Backup, Order, Payment, Product
from ..security import crypto, signing
from ..sim.rules import entropy
from . import audit, dbsec

_lock = threading.RLock()


class Volume:
    """Fictional production file volume (RAM only). 'Ransomware' only ever touches this object."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.encrypted: set[str] = set()
        self.reseed()

    def reseed(self) -> None:
        rng = __import__("random").Random(11)
        names = ["customers_2026", "orders_2026_q1", "orders_2026_q2", "inventory", "pricing_rules", "payments_ledger", "refunds",
                 "supplier_contracts", "shipping_labels", "marketing_list", "returns_log", "gst_invoices"]
        files = {}
        for i, n in enumerate(names):
            ext = ["csv", "csv", "csv", "json", "json", "csv", "csv", "txt", "csv", "csv", "csv", "csv"][i]
            lines = [f"{n},row{j},{rng.randint(1000, 99999)},NovaMart demo record,{rng.choice(['Pune', 'Chennai', 'Kochi', 'Delhi', 'Surat'])}" for j in range(70)]
            files[f"/data/{n}.{ext}"] = ("\n".join(lines)).encode()
        self.files, self.encrypted = files, set()

    def listing(self) -> list[dict]:
        return [{"path": p, "size": len(b), "entropy": round(entropy(b), 2), "status": "encrypted" if p in self.encrypted else "clean",
                 "sha256": hashlib.sha256(b).hexdigest()[:12]} for p, b in sorted(self.files.items())]

    def state(self) -> str:
        n = len(self.encrypted)
        return "healthy" if n == 0 else "encrypted" if n == len(self.files) else "partially_encrypted"


volume = Volume()


def encrypt_files(files: dict[str, bytes], limit: int | None = None) -> list[str]:
    """Sandbox 'ransomware': AES-GCM with a random throw-away key (never stored) over the given in-memory files."""
    key = os.urandom(32)
    hit = []
    for path in list(files):
        if limit is not None and len(hit) >= limit:
            break
        files[path] = crypto.seal(key, files[path], b"sandbox")
        hit.append(path)
    return hit


def ransomware_impact(actor: str) -> dict:
    """Backup-module button: encrypt the entire sandbox volume."""
    with _lock:
        before = volume.state()
        hit = encrypt_files(volume.files)
        volume.encrypted.update(hit)
    audit.log(actor, "backup.ransomware_sim", "volume:/data", {"files_encrypted": len(hit)})
    from . import state  # late import (avoids cycle)
    state.set_node("db", "compromised")
    state.set_node("cloud", "compromised")
    state.add_impact("manual-ransomware", "ransomware", 0, 25, 70)
    state.changed()
    return {"before": before, "after": volume.state(), "files_encrypted": len(hit)}


def _gather() -> dict[str, Any]:
    with session_scope() as db:
        tables = {"products": [dbsec.payload_of("product", r) | {"record_hash": r.record_hash, "signature": r.signature} for r in db.scalars(select(Product)).all()],
                  "orders": [dbsec.payload_of("order", r) | {"record_hash": r.record_hash, "signature": r.signature} for r in db.scalars(select(Order)).all()],
                  "payments": [dbsec.payload_of("payment", r) | {"record_hash": r.record_hash, "signature": r.signature} for r in db.scalars(select(Payment)).all()]}
    return {"files": {p: base64.b64encode(b).decode() for p, b in volume.files.items()}, "tables": tables}


def create_backup(label: str, kind: str, actor: str) -> dict:
    with _lock:
        if volume.encrypted:
            raise ValueError("Refusing to back up an encrypted/compromised volume — a backup of ransomware-locked data is useless.")
        snap = json.dumps(_gather(), sort_keys=True, separators=(",", ":")).encode()
    bid = "BK-" + datetime.now(timezone.utc).strftime("%y%m%d%H%M%S") + "-" + secrets.token_hex(2).upper()
    sha = hashlib.sha256(snap).hexdigest()
    sig = base64.b64encode(signing.sign(dbsec.signing_key(), sha.encode())).decode()
    blob = crypto.seal(crypto.derive_key("backup"), snap, bid.encode())
    with session_scope() as db:
        db.add(Backup(id=bid, label=label, kind=kind, file_count=len(volume.files), size_bytes=len(blob), sha256=sha, signature=sig, blob=blob,
                      status="unverified"))
    audit.log(actor, "backup.create", bid, {"files": len(volume.files), "sha256": sha[:16], "bytes": len(blob)})
    return verify_backup(bid, actor)


def _open(b: Backup) -> tuple[bytes | None, dict]:
    steps = {"decrypt": False, "hash": False, "signature": False}
    try:
        snap = crypto.unseal(crypto.derive_key("backup"), b.blob, b.id.encode())
        steps["decrypt"] = True
    except Exception:
        return None, steps
    steps["hash"] = hashlib.sha256(snap).hexdigest() == b.sha256
    steps["signature"] = signing.verify(dbsec.signing_key().public_key(), b.sha256.encode(), base64.b64decode(b.signature))
    return snap, steps


def verify_backup(bid: str, actor: str = "system") -> dict:
    with session_scope() as db:
        b = db.get(Backup, bid)
        if not b:
            raise KeyError("backup not found")
        _, steps = _open(b)
        b.status = "verified" if all(steps.values()) else "corrupt"
        b.verified_at = datetime.now(timezone.utc)
        out = to_dict(b) | {"checks": steps}
    audit.log(actor, "backup.verify", bid, {"status": out["status"], **steps})
    return out


def corrupt_backup(bid: str, actor: str) -> dict:
    """Demo of backup poisoning: flips one byte of the stored (encrypted) snapshot."""
    with session_scope() as db:
        b = db.get(Backup, bid)
        blob = bytearray(b.blob)
        blob[len(blob) // 2] ^= 0xFF
        b.blob, b.status = bytes(blob), "unverified"
    audit.log(actor, "backup.corrupt_sim", bid, {})
    return verify_backup(bid, actor)


def restore(bid: str | None, actor: str) -> dict:
    with _lock, session_scope() as db:
        b = db.get(Backup, bid) if bid else db.scalars(select(Backup).where(Backup.status == "verified").order_by(Backup.ts.desc())).first()
        if not b:
            raise ValueError("No verified backup available to restore from.")
        snap, steps = _open(b)
        if snap is None or not all(steps.values()):
            b.status = "corrupt"
            raise ValueError(f"Backup {b.id} FAILED verification {steps} — restore refused (it may have been tampered with).")
        data = json.loads(snap)
        before = volume.state()
        volume.files = {p: base64.b64decode(v) for p, v in data["files"].items()}
        volume.encrypted = set()
        for tname, model, ent in (("products", Product, "product"), ("orders", Order, "order"), ("payments", Payment, "payment")):
            for rec in data["tables"][tname]:
                row = db.get(model, rec["id"])
                if row:
                    for k, v in rec.items():
                        setattr(row, k, v)
        out = {"backup": b.id, "before": before, "after": volume.state(), "files_restored": len(volume.files),
               "checks": steps, "restored_at": datetime.now(timezone.utc).isoformat() + "Z"}
    audit.log(actor, "backup.restore", out["backup"], {"files": out["files_restored"], "checks": steps})
    from . import state
    state.resolve_pillar(None, "A")
    for n in ("db", "cloud", "app"):
        if state.live.nodes[n]["status"] in ("compromised", "degraded"):
            state.set_node(n, "healthy")
    state.changed()
    return out


def ensure_verified_backup(actor: str = "system") -> None:
    with session_scope() as db:
        ok = db.scalars(select(Backup).where(Backup.status == "verified")).first()
    if not ok and not volume.encrypted:
        create_backup("Automatic baseline snapshot", "auto", actor)


def to_dict(b: Backup) -> dict:
    ts = b.ts.replace(tzinfo=None) if b.ts.tzinfo is None else b.ts.astimezone(timezone.utc).replace(tzinfo=None)
    v = b.verified_at.replace(tzinfo=None) if b.verified_at else None
    return {"id": b.id, "ts": ts.isoformat() + "Z", "label": b.label, "kind": b.kind, "file_count": b.file_count, "size_bytes": b.size_bytes,
            "sha256": b.sha256, "signature": b.signature[:32] + "…", "status": b.status, "verified_at": (v.isoformat() + "Z") if v else None}


def status() -> dict:
    with session_scope() as db:
        bs = db.scalars(select(Backup).order_by(Backup.ts.desc())).all()
        items = [to_dict(b) for b in bs]
    last = items[0]["ts"] if items else None
    verified = [b for b in items if b["status"] == "verified"]
    age_h = None
    if verified:
        t = datetime.fromisoformat(verified[0]["ts"].rstrip("Z"))
        age_h = round((datetime.now(timezone.utc).replace(tzinfo=None) - t).total_seconds() / 3600, 2)
    health = "no_backup" if not items else "healthy" if verified and (age_h or 0) < 24 else "stale" if verified else "degraded"
    return {"backups": items, "last_backup": last, "verified_count": len(verified), "age_hours": age_h, "health": health,
            "volume": {"state": volume.state(), "files": volume.listing(), "encrypted": len(volume.encrypted), "total": len(volume.files)}}
