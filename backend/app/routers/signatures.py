from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..bus import bus
from ..db import session_scope
from ..deps import Principal, require
from ..models import Order, Payment, Product
from ..security import pki, signing
from ..services import audit, dbsec, events

router = APIRouter(prefix="/sig", tags=["signatures"])


class KeyIn(BaseModel):
    algorithm: str = Field(default="RSA-PSS", pattern=r"^(RSA-PSS|ECDSA-P256)$")


@router.post("/keys")
def gen_keys(body: KeyIn, p: Principal = Depends(require("sig:use"))):
    out = signing.lab_generate(body.algorithm)
    audit.log(p.username, "sig.keygen", out["key_id"], {"alg": body.algorithm, "fingerprint": out["fingerprint"][:16]})
    return out


@router.get("/samples")
def samples(p: Principal = Depends(require("sig:use"))):
    with session_scope() as db:
        o, pay, prod = db.get(Order, 1), db.get(Payment, 1), db.get(Product, 1)
        return {"order": dbsec.payload_of("order", o), "price": {"product_id": prod.id, "sku": prod.sku, "name": prod.name, "price": prod.price},
                "payment": dbsec.payload_of("payment", pay), "db_record": dbsec.payload_of("product", prod)}


class SignIn(BaseModel):
    key_id: str
    record: dict


@router.post("/sign")
def sign(body: SignIn, p: Principal = Depends(require("sig:use"))):
    try:
        out = signing.lab_sign(body.key_id, body.record)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e
    audit.log(p.username, "sig.sign", body.key_id, {"hash": out["hash"][:16]})
    return out


class VerifyIn(SignIn):
    signature: str
    kind: str = "record"


@router.post("/verify")
def verify(body: VerifyIn, p: Principal = Depends(require("sig:use"))):
    try:
        out = signing.lab_verify(body.key_id, body.record, body.signature)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e
    audit.log(p.username, "sig.verify", body.key_id, {"valid": out["valid"], "kind": body.kind})
    if not out["valid"]:
        ev = events.emit("integrity_violation", "app", "db", "high", "Digital signature verification failed", "Record rejected + alert raised", "detected",
                         "system", False, None, {"kind": body.kind, "hash": out["hash"][:24]})
        out["alert"] = ev
    return out


@router.get("/server-key")
def server_key(p: Principal = Depends(require("sig:use"))):
    return dbsec.key_info()


@router.get("/pki/ca")
def ca(p: Principal = Depends(require("sig:use"))):
    _, cert = pki.root_ca()
    return {**pki.describe(cert), "pem": cert.public_bytes(serialization.Encoding.PEM).decode()}


class IssueIn(BaseModel):
    hostname: str = Field(default="shop.novamart.demo", pattern=r"^[a-z0-9.-]{3,80}$")
    issuer: str = Field(default="trusted", pattern=r"^(trusted|rogue)$")
    validate_as: str = Field(default="shop.novamart.demo", pattern=r"^[a-z0-9.-]{3,80}$")


@router.post("/pki/issue")
def issue(body: IssueIn, p: Principal = Depends(require("sig:use"))):
    ca_key, ca_cert = pki.root_ca()
    if body.issuer == "trusted":
        _, cert = pki.issue(ca_key, ca_cert, body.hostname)
    else:
        rk, rc = pki.rogue_ca()
        _, cert = pki.issue(rk, rc, body.hostname, 30, "Attacker Ltd")
    res = pki.validate(cert, ca_cert, body.validate_as)
    audit.log(p.username, "pki.issue", body.hostname, {"issuer": body.issuer, "valid": res["valid"]})
    return {"certificate": pki.describe(cert), "pem": cert.public_bytes(serialization.Encoding.PEM).decode(), "validation": res, "trust_store": pki.describe(ca_cert)["subject"]}
