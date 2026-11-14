"""Storefront REST API. Public catalogue; customer-only buying/orders/profile; staff-only order review."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..deps import Principal, SlidingLimiter, client_ip, get_customer, require
from ..services import events, shop, state

router = APIRouter(prefix="/shop", tags=["shop"])
checkout_limiter = SlidingLimiter(8, 60)


# ---- public catalogue ---------------------------------------------------------------------------------
@router.get("/categories")
def categories():
    return shop.categories()


@router.get("/products")
def products(q: str = Query("", max_length=200), category: str | None = Query(None, max_length=40), sort: str = Query("featured", max_length=20)):
    status, body = shop.search(q, category, sort)
    if status != 200:
        from fastapi.responses import JSONResponse
        return JSONResponse(body, status_code=status)
    return body


@router.get("/products/{pid}")
def product(pid: int):
    p = shop.get_product(pid)
    if not p:
        raise HTTPException(404, "Product not found")
    return p


class ReviewIn(BaseModel):
    rating: int = Field(ge=1, le=5)
    body: str = Field(min_length=3, max_length=500)


@router.post("/products/{pid}/reviews")
def review(pid: int, body: ReviewIn, p: Principal = Depends(get_customer)):
    status, out = shop.add_review(p.username, pid, body.rating, body.body)
    if status != 200:
        from fastapi.responses import JSONResponse
        return JSONResponse(out, status_code=status)
    return out


# ---- customer ------------------------------------------------------------------------------------------
class CartItem(BaseModel):
    product_id: int
    qty: int = Field(ge=1, le=10)


class CheckoutIn(BaseModel):
    items: list[CartItem] = Field(min_length=1, max_length=20)
    payment_method: str = Field(max_length=24)


@router.post("/checkout")
def checkout(body: CheckoutIn, request: Request, p: Principal = Depends(get_customer)):
    from fastapi.responses import JSONResponse
    ip = client_ip(request)
    if state.live.defences.get("rate_limiting") and not checkout_limiter.allow(ip):
        events.emit("ddos", "internet", "app", "medium", "Rate limiter (8 checkouts / minute / IP)", "HTTP 429", "blocked", "storefront", False, None, {"ip": ip, "kind": "storefront"})
        return JSONResponse({"detail": "Too many checkout attempts from this address. Please wait a minute."}, status_code=429)
    status, out = shop.checkout(p.username, [i.model_dump() for i in body.items], body.payment_method)
    return JSONResponse(out, status_code=status) if status != 200 else out


@router.get("/orders")
def orders(p: Principal = Depends(get_customer)):
    return shop.my_orders(p.username)


@router.get("/orders/{order_no}")
def order(order_no: str, p: Principal = Depends(get_customer)):
    from fastapi.responses import JSONResponse
    status, out = shop.get_order(p.username, order_no)
    return JSONResponse(out, status_code=status) if status != 200 else out


class ProfileIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    phone: str = Field("", max_length=20)
    address: str = Field("", max_length=200)


@router.get("/me")
def me(p: Principal = Depends(get_customer)):
    out = shop.get_profile(p.username)
    if not out:
        raise HTTPException(404, "No customer profile")
    return out


@router.put("/me")
def update_me(body: ProfileIn, p: Principal = Depends(get_customer)):
    out = shop.update_profile(p.username, " ".join(body.name.split()), body.phone.strip(), body.address.strip())
    if not out:
        raise HTTPException(404, "No customer profile")
    return out


# ---- staff ---------------------------------------------------------------------------------------------
@router.get("/admin/summary")
def admin_summary(p: Principal = Depends(require("view"))):
    return shop.admin_summary()


@router.get("/admin/orders")
def admin_orders(status: str | None = Query(None, max_length=20), p: Principal = Depends(require("db:read"))):
    return shop.admin_orders(status)


class DecisionIn(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")


@router.post("/admin/orders/{order_no}/review")
def admin_review(order_no: str, body: DecisionIn, p: Principal = Depends(require("incident:manage"))):
    try:
        return shop.admin_decide(order_no, body.decision, p.username)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
