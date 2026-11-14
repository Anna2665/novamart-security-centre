from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..db import session_scope
from ..deps import Principal, require
from ..models import Customer, Order, Payment, Product
from ..security import crypto
from ..services import audit, dbsec

router = APIRouter(prefix="/crypto", tags=["cryptography"])


@router.get("/samples")
def samples(p: Principal = Depends(require("crypto:use"))):
    with session_scope() as db:
        c = db.get(Customer, 1)
        o = db.get(Order, 1)
        pay = db.get(Payment, 1)
        prod = db.get(Product, o.product_id)
        cust = dbsec.customer_view(c, True)
        return {"customer": f"Customer: {cust['name']} | Email: {cust['email']} | Phone: {cust['phone']} | Address: {cust['address']}",
                "order": f"Order #{o.id} | Customer #{o.customer_id} | {prod.name} x{o.quantity} | Amount: INR {o.amount:,} | Status: {o.status}",
                "transaction": f"Txn {pay.txn_ref} | Order #{pay.order_id} | INR {pay.amount:,} | {pay.method} | {pay.status}"}


class EncIn(BaseModel):
    plaintext: str = Field(min_length=1, max_length=2000)
    dataset: str = Field(default="custom", pattern=r"^[a-z_]{1,24}$")


@router.post("/aes/encrypt")
def encrypt(body: EncIn, p: Principal = Depends(require("crypto:use"))):
    out = crypto.lab_encrypt(body.plaintext, body.dataset)
    audit.log(p.username, "crypto.encrypt", body.dataset, {"bytes": out["plaintext_bytes"], "key_id": out["key_id"]})
    return out


class DecIn(BaseModel):
    blob: str
    dataset: str = Field(default="custom", pattern=r"^[a-z_]{1,24}$")
    mode: str = Field(default="correct", pattern=r"^(correct|wrong_key|tampered)$")


@router.post("/aes/decrypt")
def decrypt(body: DecIn, p: Principal = Depends(require("crypto:use"))):
    try:
        out = crypto.lab_decrypt(body.blob, body.dataset, body.mode)
    except Exception as e:
        raise HTTPException(400, f"Malformed ciphertext: {e}") from e
    audit.log(p.username, "crypto.decrypt", body.dataset, {"mode": body.mode, "verified": out["verified"]})
    return out


@router.get("/algorithms")
def algorithms(p: Principal = Depends(require("crypto:use"))):
    return {"algorithms": [{**a, "brute_force": crypto.brute_force_estimate(a["security_bits"]) if a["security_bits"] else None} for a in crypto.ALGORITHMS]}


class HashIn(BaseModel):
    a: str = Field(max_length=2000)
    b: str | None = Field(default=None, max_length=2000)


@router.post("/hash")
def hash_(body: HashIn, p: Principal = Depends(require("crypto:use"))):
    ha = crypto.sha256_hex(body.a)
    out = {"a": ha}
    if body.b is not None:
        hb = crypto.sha256_hex(body.b)
        out |= {"b": hb, "bits_changed": crypto.bit_difference(ha, hb), "of": 256}
    return out
