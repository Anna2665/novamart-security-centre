"""Idempotent first-run seeding: users, shop data (fictional), signed records, baseline backup, telemetry history."""
import os
import random
import secrets
import shutil
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, inspect, select

from ..config import settings
from ..db import Base, engine, session_scope
from ..models import Customer, Order, Payment, Product, Review, User
from ..security.passwords import hash_password
from . import audit, backup, dbsec, telemetry

PRODUCTS = [("NVB-001", "NovaBeat Pro Wireless Earbuds", "Electronics", 1499, 240), ("AFB-002", "AeroFit Smart Band 6", "Wearables", 2999, 120),
            ("TMB-003", "TrailMate 35L Backpack", "Travel", 1799, 90), ("PBK-004", "PureBrew Electric Kettle", "Home", 1199, 150),
            ("LMD-005", "LumiDesk LED Lamp", "Home", 899, 200), ("CMA-006", "ChefMate Air Fryer 4L", "Kitchen", 5499, 60),
            ("FMY-007", "FlexMat Yoga Mat", "Fitness", 699, 310), ("SSB-008", "SonicShell Bluetooth Speaker", "Electronics", 2299, 130),
            ("CCB-009", "CasaCotton Bedsheet Set", "Home", 1399, 175), ("PXT-010", "PixelPad 10\" Tablet", "Electronics", 12999, 45),
            ("VCG-011", "VoltCharge 65W GaN Charger", "Electronics", 1599, 220), ("SRS-012", "StrideRun Running Shoes", "Fashion", 3299, 85)]
CUSTOMERS = [("Asha Rao", "asha.rao@example.com", "+91 90000 11201", "12 Lake View Rd, Bengaluru 560001", "gold"),
             ("Vikram Nair", "vikram.nair@example.com", "+91 90000 11202", "7 Marine Drive, Kochi 682001", "standard"),
             ("Meera Iyer", "meera.iyer@example.com", "+91 90000 11203", "44 Anna Salai, Chennai 600002", "platinum"),
             ("Rohan Desai", "rohan.desai@example.com", "+91 90000 11204", "3 FC Road, Pune 411004", "standard"),
             ("Ishita Sen", "ishita.sen@example.com", "+91 90000 11205", "19 Park Street, Kolkata 700016", "gold"),
             ("Karthik Reddy", "karthik.reddy@example.com", "+91 90000 11206", "88 Banjara Hills, Hyderabad 500034", "standard"),
             ("Nisha Verma", "nisha.verma@example.com", "+91 90000 11207", "5 Connaught Place, Delhi 110001", "standard"),
             ("Aarav Shah", "aarav.shah@example.com", "+91 90000 11208", "21 CG Road, Ahmedabad 380009", "gold")]
USERS = [("admin", "admin", "cg_admin_password"), ("analyst", "analyst", "cg_analyst_password"), ("viewer", "viewer", "cg_viewer_password"),
         ("shopper", "customer", "cg_shopper_password")]
DESCRIPTIONS = {
    "NVB-001": "True wireless earbuds with active noise cancellation, 28-hour battery life and a pocket-sized charging case.",
    "AFB-002": "Slim fitness band with heart-rate and sleep tracking, 14-day battery and water resistance up to 50 m.",
    "TMB-003": "35-litre water-resistant backpack with a padded laptop sleeve, rain cover and ventilated back panel.",
    "PBK-004": "1.7-litre stainless-steel electric kettle with auto shut-off and boil-dry protection.",
    "LMD-005": "Dimmable LED desk lamp with three colour temperatures and a USB charging port.",
    "CMA-006": "4-litre air fryer with digital presets. Cooks crisp food with up to 90% less oil.",
    "FMY-007": "6 mm non-slip yoga mat with alignment lines and a carry strap.",
    "SSB-008": "Portable Bluetooth speaker with 360-degree sound, IPX7 waterproofing and 12-hour playtime.",
    "CCB-009": "Soft 100% cotton double bedsheet set with two pillow covers. Machine washable.",
    "PXT-010": "10-inch tablet with a bright 2K display, 128 GB storage and all-day battery.",
    "VCG-011": "Compact 65 W GaN fast charger that powers a laptop, phone and earbuds from one plug.",
    "SRS-012": "Lightweight cushioned running shoes with a breathable mesh upper and grippy outsole.",
}
REVIEWS = [(5, "Excellent quality, arrived earlier than expected."), (4, "Good value for money. Does exactly what it says."), (5, "Really happy with this purchase."),
           (3, "Decent, but the packaging could be better."), (4, "Solid build and easy to use."), (5, "Would definitely buy again."),
           (4, "Works great, my family loves it."), (3, "Okay for the price. Nothing special."), (5, "Better than I expected. Highly recommend.")]


def _upgrade_old_schema() -> None:
    """A data folder from an older version has a different schema. Keep it aside (SQLite) and start fresh instead of crashing."""
    insp = inspect(engine)
    if not insp.has_table("users") or "full_name" in {c["name"] for c in insp.get_columns("users")}:
        return
    if engine.dialect.name != "sqlite":
        raise RuntimeError("The database schema is from an older version. Drop the database, or run `python -m alembic upgrade head` from the backend folder.")
    path = engine.url.database
    engine.dispose()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(path + suffix):
            shutil.move(path + suffix, f"{path}{suffix}.old-{stamp}")
    print(f"\n  Found data from an older version. It was kept as {os.path.basename(path)}.old-{stamp}; starting with a fresh database.\n")


def init() -> None:
    _upgrade_old_schema()
    Base.metadata.create_all(engine)
    dbsec.signing_key()  # create/load the record-signing key before any write transaction is open
    creds = []
    with session_scope() as db:
        for uname, role, attr in USERS:
            if db.scalar(select(User).where(User.username == uname)):
                continue
            pw = getattr(settings, attr) or secrets.token_urlsafe(12) + "A1!"
            db.add(User(username=uname, email=settings.demo_email, password_hash=hash_password(pw), role=role,
                        full_name="Demo Shopper" if role == "customer" else uname.capitalize()))
            creds.append((uname, pw, bool(getattr(settings, attr))))
        if (db.scalar(select(func.count(Product.id))) or 0) == 0:
            rng = random.Random(5)
            for sku, name, cat, price, stock in PRODUCTS:
                db.add(Product(sku=sku, name=name, category=cat, price=price, stock=stock, description=DESCRIPTIONS.get(sku, "")))
            db.flush()
            for n, e, ph, ad, tier in CUSTOMERS:
                c = Customer(name=n, tier=tier, email_enc="", phone_enc="", address_enc="")
                db.add(c)
                db.flush()
                c.email_enc, c.phone_enc, c.address_enc = (dbsec.enc_field(c.id, "email", e), dbsec.enc_field(c.id, "phone", ph), dbsec.enc_field(c.id, "address", ad))
            db.flush()
            prods = db.scalars(select(Product)).all()
            now = datetime.now(timezone.utc)
            shopper = db.scalar(select(User).where(User.username == "shopper"))
            if shopper:  # the demo shopper is customer #9, so the store has a real account to sign in with
                sc = Customer(name="Demo Shopper", tier="standard", email_enc="", phone_enc="", address_enc="", user_id=shopper.id)
                db.add(sc)
                db.flush()
                sc.email_enc, sc.phone_enc, sc.address_enc = (dbsec.enc_field(sc.id, "email", shopper.email), dbsec.enc_field(sc.id, "phone", "+91 98765 43210"),
                                                              dbsec.enc_field(sc.id, "address", "14 MG Road, Bengaluru 560001"))
            total_customers = db.scalar(select(func.count(Customer.id))) or len(CUSTOMERS)
            for i in range(14 + (3 if shopper else 0)):
                p, q = rng.choice(prods), rng.randint(1, 3)
                cu = total_customers if i >= 14 else rng.randint(1, len(CUSTOMERS))  # the last three orders belong to the demo shopper
                o = Order(customer_id=cu, product_id=p.id, quantity=q, amount=p.price * q, status=rng.choice(["paid", "paid", "shipped", "delivered"]),
                          created_at=now - timedelta(days=rng.randint(1, 25), hours=rng.randint(0, 20)))
                db.add(o)
                db.flush()
                o.order_no = f"NM-{1000 + o.id}"
                db.add(Payment(order_id=o.id, amount=o.amount, method=rng.choice(["UPI", "Card", "Cash on delivery"]), status="captured", txn_ref="TXN" + secrets.token_hex(5).upper()))
            for p in prods:
                for _ in range(rng.randint(1, 3)):
                    rating, text = rng.choice(REVIEWS)
                    db.add(Review(product_id=p.id, author=rng.choice(CUSTOMERS)[0], rating=rating, body=text, created_at=now - timedelta(days=rng.randint(1, 40))))
            db.flush()
            for p in prods:
                dbsec.seal_row(db, "product", p)
            for o in db.scalars(select(Order)).all():
                dbsec.seal_row(db, "order", o)
            for pay in db.scalars(select(Payment)).all():
                dbsec.seal_row(db, "payment", pay)
    if creds:
        path = os.path.join(settings.data_dir, "demo_credentials.txt")
        with open(path, "w") as f:
            f.write("\n".join(f"{u}: {p}" for u, p, _ in creds))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        generated = [(u, p) for u, p, from_env in creds if not from_env]
        if generated:
            print("\n  Demo accounts created (one-time display, also saved to data/demo_credentials.txt):")
            for u, p in generated:
                print(f"    {u:8s} / {p}")
            print()
    telemetry.seed_history()
    backup.ensure_verified_backup("system")
    if audit.count() == 0:
        audit.log("system", "platform.init", "cyberguard-x", {"note": "database seeded with fictional NovaMart data"})


def reset_data() -> None:
    """Reset simulation state: defences ON, nodes healthy, impacts cleared, volume reseeded, tampered records restored."""
    from . import state
    from ..sim import engine
    engine.cancel()
    state.live.reset(seed_history=False)
    state.live.history = []
    backup.volume.reseed()
    dbsec.restore_all("reset")
    state.record_history()
    state.changed()
