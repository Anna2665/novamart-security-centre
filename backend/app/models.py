from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from .db import Base


def now() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Stored as UTC; always handed back to Python as *naive UTC*.

    SQLite drops time zones and PostgreSQL's TIMESTAMPTZ returns aware values in the
    session zone. Normalising here makes both databases behave identically, so the
    rest of the code never has to guess which kind of datetime it received.
    """
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="viewer")
    full_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    totp_secret_enc: Mapped[str | None] = mapped_column(String(255), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)
    last_login: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class LoginAudit(Base):
    __tablename__ = "login_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=now, index=True)
    username: Mapped[str] = mapped_column(String(64))
    ip: Mapped[str] = mapped_column(String(64), default="")
    method: Mapped[str] = mapped_column(String(32))
    result: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str] = mapped_column(String(255), default="")


class OtpChallenge(Base):
    __tablename__ = "otp_challenges"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    code_hash: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    resend_count: Mapped[int] = mapped_column(Integer, default=0)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)
    last_sent_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)
    delivery_status: Mapped[str] = mapped_column(String(32), default="pending")
    delivery_detail: Mapped[str] = mapped_column(String(255), default="")


class Product(Base):
    __tablename__ = "products"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sku: Mapped[str] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(48))
    price: Mapped[int] = mapped_column(Integer)  # INR
    stock: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(Text, default="")
    record_hash: Mapped[str] = mapped_column(String(64), default="")
    signature: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)


class Customer(Base):
    __tablename__ = "customers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    tier: Mapped[str] = mapped_column(String(24), default="standard")
    email_enc: Mapped[str] = mapped_column(Text)
    phone_enc: Mapped[str] = mapped_column(Text)
    address_enc: Mapped[str] = mapped_column(Text)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)


class Order(Base):
    __tablename__ = "orders"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id"))
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"))
    quantity: Mapped[int] = mapped_column(Integer)
    amount: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), default="paid")
    order_no: Mapped[str] = mapped_column(String(24), default="", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)
    record_hash: Mapped[str] = mapped_column(String(64), default="")
    signature: Mapped[str] = mapped_column(Text, default="")


class Payment(Base):
    __tablename__ = "payments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[int] = mapped_column(ForeignKey("orders.id"))
    amount: Mapped[int] = mapped_column(Integer)
    method: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(24), default="captured")
    txn_ref: Mapped[str] = mapped_column(String(32))
    record_hash: Mapped[str] = mapped_column(String(64), default="")
    signature: Mapped[str] = mapped_column(Text, default="")


class Review(Base):
    __tablename__ = "reviews"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), index=True)
    author: Mapped[str] = mapped_column(String(120))
    rating: Mapped[int] = mapped_column(Integer)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)


class RecordVersion(Base):
    """Append-only, signed history of authorised record versions (the 'trusted original')."""
    __tablename__ = "record_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity: Mapped[str] = mapped_column(String(24), index=True)
    entity_id: Mapped[int] = mapped_column(Integer, index=True)
    version: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict] = mapped_column(JSON)
    record_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(Text)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=now, index=True)
    attack_type: Mapped[str] = mapped_column(String(48), index=True)
    source_node: Mapped[str] = mapped_column(String(32))
    target_node: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    detection: Mapped[str] = mapped_column(String(160), default="")
    action: Mapped[str] = mapped_column(String(160), default="")
    result: Mapped[str] = mapped_column(String(24))
    origin: Mapped[str] = mapped_column(String(16), default="user_run")  # seed | background | user_run | system
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    run_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class SimRun(Base):
    __tablename__ = "sim_runs"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=now, index=True)
    scenario_id: Mapped[str] = mapped_column(String(48))
    result: Mapped[str] = mapped_column(String(24))
    mode: Mapped[str] = mapped_column(String(16))
    detected: Mapped[bool] = mapped_column(Boolean, default=False)
    severity: Mapped[str] = mapped_column(String(16))
    defences: Mapped[dict] = mapped_column(JSON)
    payload: Mapped[dict] = mapped_column(JSON)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(16), unique=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | contained | resolved
    phase: Mapped[int] = mapped_column(Integer, default=1)  # 0..5 index; 1 = Identification (auto-started)
    detection_source: Mapped[str] = mapped_column(String(200), default="")
    affected_assets: Mapped[list] = mapped_column(JSON, default=list)
    checklist: Mapped[list] = mapped_column(JSON, default=list)
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    audit: Mapped[list] = mapped_column(JSON, default=list)
    run_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    scenario_id: Mapped[str | None] = mapped_column(String(48), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=now, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(120), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))


class Backup(Base):
    __tablename__ = "backups"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=now)
    label: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(16), default="manual")
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(Text)
    blob: Mapped[bytes] = mapped_column(LargeBinary)  # nonce || ciphertext || tag  (AES-256-GCM)
    status: Mapped[str] = mapped_column(String(16), default="unverified")  # unverified | verified | corrupt
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class DbAccessLog(Base):
    __tablename__ = "db_access_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=now, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(32))
    table_name: Mapped[str] = mapped_column(String(48))
    operation: Mapped[str] = mapped_column(String(24))
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    rows: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str] = mapped_column(String(200), default="")


class KV(Base):
    __tablename__ = "kv"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[float] = mapped_column(Float, default=0.0)
