"""NovaMart storefront: catalogue, search, reviews, checkout, orders and the staff fraud-review queue.

Every security decision here is made by the same real rules and the same defence switches the Security Centre uses.
When a defence is ON the attack is stopped; when it is OFF the attack succeeds against an isolated mock (never real data).
Attacks on the shop are also replayed in the Security Centre by triggering the matching lab scenario.
"""
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select

from ..db import session_scope
from ..models import Customer, Order, Payment, Product, Review, User
from ..sim import engine, rules
from . import audit, dbsec, email, events, state

CATEGORIES = ["Electronics", "Wearables", "Home", "Kitchen", "Fitness", "Travel", "Fashion"]
PAYMENT_METHODS = {"UPI": "captured", "Card": "captured", "Cash on delivery": "pending"}
REVIEW_THRESHOLD = 60  # fraud risk score at or above which an order is held for staff review
_META = re.compile(r"['\";]|--|/\*|\*/")


def _on(defence: str) -> bool:
    return bool(state.live.defences.get(defence))


def _bridge(scenario: str, params: dict) -> str | None:
    """Replay a live storefront attack in the Security Centre (pipeline, CIA impact, incident). Skipped if a run is in progress."""
    try:
        return engine.execute(scenario, params, "storefront")["run_id"]
    except engine.Busy:
        return None
    except Exception:  # noqa: BLE001 - the shop must keep working whatever the lab does
        return None


def _iso(ts: datetime | None) -> str | None:
    if ts is None:
        return None
    return (ts.astimezone(timezone.utc).replace(tzinfo=None) if ts.tzinfo else ts).isoformat() + "Z"


# ------------------------------------------------------------------------------------------------ catalogue
def _ratings(db) -> dict[int, tuple[float, int]]:
    rows = db.execute(select(Review.product_id, func.avg(Review.rating), func.count(Review.id)).group_by(Review.product_id)).all()
    return {pid: (round(float(avg), 1), int(n)) for pid, avg, n in rows}


def _product_dict(p: Product, ratings: dict[int, tuple[float, int]]) -> dict[str, Any]:
    intact = dbsec.verify_row("product", p)["intact"]
    held = (not intact) and (_on("digital_signatures") or _on("db_integrity"))  # a failed check only blocks sales when a defence is watching
    avg, n = ratings.get(p.id, (0.0, 0))
    return {"id": p.id, "sku": p.sku, "name": p.name, "category": p.category, "price": None if held else p.price, "stock": p.stock,
            "description": p.description, "rating": avg, "reviews": n, "price_verified": not held, "available": p.stock > 0 and not held}


def categories() -> list[str]:
    return CATEGORIES


def _plain_search(db, q: str, category: str | None, sort: str) -> list[Product]:
    stmt = select(Product)
    if category and category != "All":
        stmt = stmt.where(Product.category == category)
    if q:  # parameterised: the search text is always bound as data
        stmt = stmt.where(or_(Product.name.contains(q, autoescape=True), Product.category.contains(q, autoescape=True), Product.description.contains(q, autoescape=True)))
    order = {"price_asc": Product.price.asc(), "price_desc": Product.price.desc(), "name": Product.name.asc()}.get(sort, Product.id.asc())
    return list(db.scalars(stmt.order_by(order)).all())


def search(q: str, category: str | None = None, sort: str = "featured") -> tuple[int, dict]:
    """Product search. Returns (http_status, body). A body may carry a `security` block describing an attack that was seen."""
    q = (q or "").strip()[:120]
    sig = rules.waf_sqli(q) if q else None
    suspicious = bool(sig or (q and _META.search(q)))
    security: dict[str, Any] | None = None

    if suspicious:
        node = "internet"
        if sig and _on("waf"):
            by, status = f"Web Application Firewall — rule {sig.id}: {sig.name}", 403
            result, msg = "blocked", "Request blocked by the Web Application Firewall."
        elif _on("input_validation"):
            by, status = "Input validation — characters not allowed in a search", 400
            result, msg = "blocked", "That search contains characters that are not allowed."
        elif _on("sqli_protection"):
            by, status = "Parameterised query — the text was treated as data", 200
            result, msg = "neutralised", "The query was parameterised, so the text was searched as plain words and found nothing."
        else:
            by, status, result, msg = None, 200, "breach", ""
        security = {"attack": "sql_injection", "result": result, "by": by, "payload": q, "message": msg, "detected": _on("ids") or result != "breach"}

        if result == "breach":
            with session_scope() as db:
                cat = [(p.id, p.name, p.category, p.price) for p in db.scalars(select(Product).order_by(Product.id)).all()]
            m = rules.mock_search(q, cat)
            security.update(query=m["query"], leaked=m["leaked"], error=m["error"])
            security["message"] = (f"The search returned {len(m['leaked'])} row(s) that are not on sale — data the page was never meant to show." if m["leaked"]
                                   else "The injected text reached the database, but nothing sensitive came back this time.")
            if m["leaked"]:
                audit.log("anonymous", "shop.sqli_breach", "search", {"payload": q, "leaked": len(m["leaked"])})
        run_id = _bridge("sqli", {"payload": q})
        security["lab_run"] = run_id
        if run_id is None:  # lab busy: still record what the live rules decided
            events.emit("sqli", node, "app", "high", by or "None — undetected", "Search request blocked" if result == "blocked" else "Request processed",
                        "blocked" if result in ("blocked", "neutralised") else "breach", "storefront", False, None, {"payload": q, "kind": "storefront"})
        if status != 200:
            return status, {"detail": msg, "security": security, "products": []}
        if result == "breach":
            return 200, {"products": [], "total": 0, "security": security}

    with session_scope() as db:
        rt = _ratings(db)
        items = [_product_dict(p, rt) for p in _plain_search(db, q, category, sort)]
    body: dict[str, Any] = {"products": items, "total": len(items)}
    if security:
        body["security"] = security
    return 200, body


def get_product(pid: int) -> dict | None:
    with session_scope() as db:
        p = db.get(Product, pid)
        if not p:
            return None
        out = _product_dict(p, _ratings(db))
        revs = db.scalars(select(Review).where(Review.product_id == pid).order_by(Review.id.desc()).limit(30)).all()
        out["reviews_list"] = [{"id": r.id, "author": r.author, "rating": r.rating, "body": r.body, "created_at": _iso(r.created_at)} for r in revs]
        return out


# ------------------------------------------------------------------------------------------------ reviews
def add_review(username: str, pid: int, rating: int, body: str) -> tuple[int, dict]:
    body = body.strip()
    with session_scope() as db:
        p = db.get(Product, pid)
        u = db.scalar(select(User).where(User.username == username))
        if not p or not u:
            return 404, {"detail": "Product not found"}
        author = u.full_name or u.username
    xss = rules.waf_xss(body)
    security: dict[str, Any] | None = None
    stored = body
    if xss:
        if _on("waf"):
            security = {"attack": "xss", "result": "blocked", "by": f"Web Application Firewall — rule {xss.id}: {xss.name}", "payload": body[:200]}
            security["lab_run"] = _bridge("xss", {"payload": body})
            return 403, {"detail": "Your review was blocked by the Web Application Firewall because it contains script-like content.", "security": security}
        if _on("input_validation"):
            stored = rules.sanitise_html(body)
            security = {"attack": "xss", "result": "neutralised", "by": "Input sanitisation — the markup was removed before saving", "payload": body[:200]}
        else:
            security = {"attack": "xss", "result": "breach", "by": None, "payload": body[:200],
                        "message": "The review was saved exactly as typed. On a vulnerable page that script would run in every visitor's browser."}
            audit.log(username, "shop.xss_stored", f"product:{pid}", {"payload": body[:120]})
        security["lab_run"] = _bridge("xss", {"payload": body})
    with session_scope() as db:
        db.add(Review(product_id=pid, author=author, rating=rating, body=stored))
    out: dict[str, Any] = {"ok": True}
    if security:
        out["security"] = security
    return 200, out


# ------------------------------------------------------------------------------------------------ risk scoring
def risk_score(total: int, max_qty: int, recent_orders: int, account_age_hours: float) -> tuple[int, list[str]]:
    """Rule-based fraud score 0-100. Orders at or above REVIEW_THRESHOLD are held for a staff decision."""
    score, why = 0, []
    if total >= 50000:
        score += 45
        why.append(f"very high order value (₹{total:,})")
    elif total >= 25000:
        score += 20
        why.append(f"high order value (₹{total:,})")
    if max_qty >= 5:
        score += 15
        why.append(f"unusual quantity ({max_qty} of one item)")
    if recent_orders >= 3:
        score += 35
        why.append(f"{recent_orders} orders in the last 10 minutes")
    if account_age_hours < 24 and total >= 15000:
        score += 20
        why.append("new account with a large order")
    return min(score, 100), why


# ------------------------------------------------------------------------------------------------ checkout
def _customer(db, username: str) -> tuple[User, Customer] | tuple[None, None]:
    u = db.scalar(select(User).where(User.username == username))
    c = db.scalar(select(Customer).where(Customer.user_id == u.id)) if u else None
    return (u, c) if c else (None, None)


def checkout(username: str, items: list[dict], method: str) -> tuple[int, dict]:
    if method not in PAYMENT_METHODS:
        return 422, {"detail": "Choose a payment method."}
    with session_scope() as db:
        user, cust = _customer(db, username)
        if not cust:
            return 403, {"detail": "No customer profile for this account."}
        lines, total, max_qty, tampered = [], 0, 0, []
        for it in items:
            p = db.get(Product, int(it["product_id"]))
            qty = int(it["qty"])
            if not p or qty < 1 or qty > 10:
                return 422, {"detail": "One of the items in your cart is not valid."}
            check = dbsec.verify_row("product", p)
            if not check["intact"]:
                if _on("digital_signatures") or _on("db_integrity"):
                    by = "Digital signature check on the product record" if _on("digital_signatures") else "Database integrity monitoring"
                    events.emit("integrity_violation", "internet", "db", "high", by, "Checkout refused — price failed verification", "blocked", "storefront", False,
                                None, {"product": p.name, "stored_price": p.price, "kind": "storefront"})
                    return 409, {"detail": f"“{p.name}” is temporarily unavailable while we verify its price. Nothing was charged.",
                                 "security": {"attack": "price_tampering", "result": "blocked", "by": by, "product": p.name}}
                tampered.append(p)
            if p.stock < qty:
                return 409, {"detail": f"Only {p.stock} of “{p.name}” left in stock."}
            lines.append((p, qty))
            total += p.price * qty  # always priced from the database, never from the browser
            max_qty = max(max_qty, qty)
        recent = db.scalar(select(func.count(func.distinct(Order.order_no))).where(Order.customer_id == cust.id,
                           Order.created_at >= datetime.now(timezone.utc) - timedelta(minutes=10))) or 0
        age_h = (datetime.now(timezone.utc) - (cust.created_at if cust.created_at.tzinfo else cust.created_at.replace(tzinfo=timezone.utc))).total_seconds() / 3600
        score, why = risk_score(total, max_qty, int(recent), age_h)
        status = "review" if score >= REVIEW_THRESHOLD else "paid"
        order_no = f"NM-{1001 + (db.scalar(select(func.max(Order.id))) or 0)}"
        txn = "TXN" + secrets.token_hex(5).upper()
        made: list[tuple[Order, Product, int]] = []
        for p, qty in lines:
            o = Order(customer_id=cust.id, product_id=p.id, quantity=qty, amount=p.price * qty, status=status, order_no=order_no, risk_score=score)
            db.add(o)
            db.flush()
            pay = Payment(order_id=o.id, amount=o.amount, method=method, status="held" if status == "review" else PAYMENT_METHODS[method], txn_ref=txn)
            db.add(pay)
            db.flush()
            dbsec.seal_row(db, "order", o)
            dbsec.seal_row(db, "payment", pay)
            p.stock -= qty
            made.append((o, p, qty))
        name, to = user.full_name or user.username, user.email
        receipt = [{"name": p.name, "qty": q, "amount": o.amount} for o, p, q in made]
        tampered_names = [p.name for p in tampered]
    if tampered:
        events.emit("db_tamper", "internet", "db", "critical", "None — undetected", "Order accepted at a price that fails its signature check", "breach", "storefront",
                    False, None, {"order": order_no, "products": tampered_names, "paid": total, "kind": "storefront"})
    audit.log(username, "shop.checkout", order_no, {"total": total, "status": status, "risk": score})
    out: dict[str, Any] = {"order_no": order_no, "total": total, "status": status, "risk_score": score, "risk_reasons": why, "payment_method": method}
    if tampered:
        out["security"] = {"attack": "price_tampering", "result": "breach", "by": None,
                           "message": "This order was accepted at a price that fails its signature check — nothing was watching the price."}
    if status == "review":
        events.emit("exfiltration", "internet", "app", "medium", f"Order risk engine (score {score}/100)", "Order held for manual review", "contained", "storefront", False, None,
                    {"order": order_no, "reasons": why, "kind": "storefront"})
        out["receipt_email"] = {"status": "skipped", "detail": "Held for review — the receipt is sent once staff approve the order."}
    else:
        r = email.send_order_receipt(to, name, order_no, receipt, total, method + " (demo)")
        out["receipt_email"] = {"status": r.status, "detail": r.detail}
    return 200, out


# ------------------------------------------------------------------------------------------------ orders
def _group(db, lines: list[Order], with_customer: bool = False) -> dict[str, Any]:
    names = {p.id: p.name for p in db.scalars(select(Product).where(Product.id.in_({o.product_id for o in lines}))).all()}
    pays = {p.order_id: p for p in db.scalars(select(Payment).where(Payment.order_id.in_([o.id for o in lines]))).all()}
    first = lines[0]
    pay = pays.get(first.id)
    out = {"order_no": first.order_no, "date": _iso(first.created_at), "status": first.status, "total": sum(o.amount for o in lines), "risk_score": first.risk_score,
           "items": [{"name": names.get(o.product_id, "?"), "qty": o.quantity, "amount": o.amount, "product_id": o.product_id} for o in lines],
           "payment": {"method": pay.method if pay else "", "status": pay.status if pay else "", "ref": pay.txn_ref if pay else ""}}
    if with_customer:
        c = db.get(Customer, first.customer_id)
        out["customer"] = c.name if c else "?"
        out["customer_id"] = first.customer_id
    return out


def my_orders(username: str) -> list[dict]:
    with session_scope() as db:
        _, cust = _customer(db, username)
        if not cust:
            return []
        rows = db.scalars(select(Order).where(Order.customer_id == cust.id).order_by(Order.id.desc())).all()
        groups: dict[str, list[Order]] = {}
        for o in rows:
            groups.setdefault(o.order_no or f"#{o.id}", []).append(o)
        return [_group(db, v) for v in groups.values()]


def get_order(username: str, order_no: str) -> tuple[int, dict]:
    """Ownership check (broken-access-control / IDOR demo): a customer may only read their own orders."""
    with session_scope() as db:
        _, cust = _customer(db, username)
        lines = list(db.scalars(select(Order).where(Order.order_no == order_no).order_by(Order.id)).all())
        if not cust or not lines:
            return 404, {"detail": "Order not found."}
        grp = _group(db, lines, with_customer=True)
        mine = lines[0].customer_id == cust.id
    if mine:
        grp.pop("customer", None), grp.pop("customer_id", None)
        return 200, grp
    if _on("rbac"):
        events.emit("exfiltration", "internet", "app", "high", "Ownership check (RBAC)", "HTTP 403 — order belongs to another customer", "blocked", "storefront", False,
                    None, {"user": username, "order": order_no, "kind": "storefront"})
        audit.log(username, "rbac.denied", f"order:{order_no}", {})
        return 403, {"detail": "You don't have access to this order.", "security": {"attack": "idor", "result": "blocked", "by": "Ownership check (role-based access control)"}}
    events.emit("exfiltration", "internet", "app", "critical", "IDS alert" if _on("ids") else "None — undetected", "Order of another customer returned", "breach", "storefront",
                False, None, {"user": username, "order": order_no, "owner": grp.get("customer"), "kind": "storefront"})
    audit.log(username, "shop.idor_breach", f"order:{order_no}", {"owner": grp.get("customer")})
    grp["security"] = {"attack": "idor", "result": "breach", "by": None,
                       "message": f"This order belongs to {grp.get('customer')}. Without an ownership check, any customer can read any order by changing the number."}
    return 200, grp


# ------------------------------------------------------------------------------------------------ profile
def get_profile(username: str) -> dict | None:
    with session_scope() as db:
        u, c = _customer(db, username)
        if not c:
            return None
        return {"name": c.name, "email": u.email, "phone": dbsec.dec_field(c.id, "phone", c.phone_enc), "address": dbsec.dec_field(c.id, "address", c.address_enc),
                "tier": c.tier, "member_since": _iso(c.created_at), "totp_enabled": u.totp_enabled}


def update_profile(username: str, name: str, phone: str, address: str) -> dict | None:
    with session_scope() as db:
        u, c = _customer(db, username)
        if not c:
            return None
        c.name, u.full_name = name, name
        c.phone_enc = dbsec.enc_field(c.id, "phone", phone)
        c.address_enc = dbsec.enc_field(c.id, "address", address)
    audit.log(username, "shop.profile_update", "", {})
    return get_profile(username)


# ------------------------------------------------------------------------------------------------ staff
def admin_orders(status: str | None = None, limit: int = 60) -> list[dict]:
    with session_scope() as db:
        rows = db.scalars(select(Order).order_by(Order.id.desc()).limit(limit * 4)).all()
        groups: dict[str, list[Order]] = {}
        for o in rows:
            groups.setdefault(o.order_no or f"#{o.id}", []).append(o)
        out = [_group(db, v, with_customer=True) for v in groups.values()]
    out = [g for g in out if not status or g["status"] == status]
    return out[:limit]


def admin_decide(order_no: str, decision: str, actor: str) -> dict:
    """Staff approve or reject an order held by the risk engine. Records are re-signed so the ledger stays trustworthy."""
    with session_scope() as db:
        lines = list(db.scalars(select(Order).where(Order.order_no == order_no)).all())
        if not lines:
            raise KeyError("order not found")
        if lines[0].status != "review":
            raise ValueError("This order is not waiting for review.")
        ok = decision == "approve"
        for o in lines:
            o.status = "paid" if ok else "cancelled"
            pay = db.scalar(select(Payment).where(Payment.order_id == o.id))
            if pay:
                pay.status = "captured" if ok else "refunded"
                dbsec.seal_row(db, "payment", pay)
            if not ok:
                p = db.get(Product, o.product_id)
                if p:
                    p.stock += o.quantity
            dbsec.seal_row(db, "order", o)
        cust = db.get(Customer, lines[0].customer_id)
        user = db.get(User, cust.user_id) if cust and cust.user_id else None
        name, to = (user.full_name or user.username, user.email) if user else (None, None)
        receipt = [{"name": (db.get(Product, o.product_id).name), "qty": o.quantity, "amount": o.amount} for o in lines]
        total, method = sum(o.amount for o in lines), (db.scalar(select(Payment.method).where(Payment.order_id == lines[0].id)) or "")
    audit.log(actor, f"shop.order_{decision}", order_no, {})
    if ok and to:
        email.send_order_receipt(to, name, order_no, receipt, total, method + " (demo)")
    return {"order_no": order_no, "status": "paid" if ok else "cancelled"}


def admin_summary() -> dict:
    with session_scope() as db:
        orders = db.scalars(select(Order)).all()
        live = [o for o in orders if o.status not in ("cancelled",)]
        return {"orders": len({o.order_no or o.id for o in orders}), "revenue": sum(o.amount for o in live if o.status != "review"),
                "held": len({o.order_no for o in orders if o.status == "review"}), "customers": db.scalar(select(func.count(Customer.id))) or 0,
                "products": db.scalar(select(func.count(Product.id))) or 0}
