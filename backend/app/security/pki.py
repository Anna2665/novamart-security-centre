"""Tiny PKI: a persistent CyberGuard root CA, server certificates and real chain validation (used for the MITM demo)."""
import datetime as dt
import threading
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from . import crypto
from .signing import private_pem

_lock = threading.Lock()
_rogue: dict[str, Any] = {}


def _name(cn: str, org: str = "NovaMart Demo") -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def new_ca(cn: str, org: str):
    key = rsa.generate_private_key(65537, 2048)
    name = _name(cn, org)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(_utc() - dt.timedelta(minutes=5))
            .not_valid_after(_utc() + dt.timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256()))
    return key, cert


def issue(ca_key, ca_cert, hostname: str, days: int = 90, org: str = "NovaMart Demo"):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name(hostname, org)).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_utc() - dt.timedelta(minutes=5)).not_valid_after(_utc() + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
    return key, cert


def root_ca():
    """Persistent root CA; private key stored encrypted with the master-key-derived wrap key."""
    from ..db import session_scope
    from ..models import KV
    with _lock, session_scope() as db:
        row = db.get(KV, "root_ca")
        if row:
            key = serialization.load_pem_private_key(
                crypto.unseal(crypto.derive_key("ca-wrap"), bytes.fromhex(row.value["key_sealed"])), None)
            return key, x509.load_pem_x509_certificate(row.value["cert_pem"].encode())
        key, cert = new_ca("CyberGuard Root CA", "CyberGuard X Demo PKI")
        db.add(KV(key="root_ca", updated_at=0.0, value={
            "key_sealed": crypto.seal(crypto.derive_key("ca-wrap"), private_pem(key)).hex(),
            "cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode()}))
        return key, cert


def rogue_ca():
    with _lock:
        if not _rogue:
            _rogue["key"], _rogue["cert"] = new_ca("Totally Legit Certificate Authority", "Attacker Ltd")
        return _rogue["key"], _rogue["cert"]


def describe(cert: x509.Certificate) -> dict[str, Any]:
    cn = lambda n: (n.get_attributes_for_oid(NameOID.COMMON_NAME) or [None])[0].value  # noqa: E731
    return {"subject": cn(cert.subject), "issuer": cn(cert.issuer), "serial": format(cert.serial_number, "x")[:20],
            "not_before": cert.not_valid_before_utc.isoformat(), "not_after": cert.not_valid_after_utc.isoformat(),
            "sha256": cert.fingerprint(hashes.SHA256()).hex(), "signature_algorithm": cert.signature_hash_algorithm.name.upper() + " with " +
            ("RSA" if isinstance(cert.public_key(), rsa.RSAPublicKey) else "ECDSA") + " key",
            "public_key": "RSA-2048" if isinstance(cert.public_key(), rsa.RSAPublicKey) else "ECDSA P-256"}


def validate(cert: x509.Certificate, trusted_ca: x509.Certificate, hostname: str) -> dict[str, Any]:
    """Real chain validation: issuer match, signature by the trusted CA key, validity window and hostname (SAN)."""
    checks = []
    now = _utc()
    checks.append({"check": "Issuer is a trusted CA", "ok": cert.issuer == trusted_ca.subject,
                   "detail": f"issuer={describe(cert)['issuer']} trusted={describe(trusted_ca)['subject']}"})
    try:
        cert.verify_directly_issued_by(trusted_ca)
        sig_ok = True
    except Exception:  # signature / issuer mismatch
        sig_ok = False
    checks.append({"check": "Signature verifies with the trusted CA public key", "ok": sig_ok,
                   "detail": "RSA signature valid" if sig_ok else "signature does not verify against the trust store"})
    in_window = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
    checks.append({"check": "Certificate within validity period", "ok": in_window,
                   "detail": f"{cert.not_valid_before_utc:%Y-%m-%d} → {cert.not_valid_after_utc:%Y-%m-%d}"})
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    checks.append({"check": "Hostname matches certificate", "ok": hostname in names, "detail": f"want {hostname}; cert covers {names or '—'}"})
    return {"valid": all(c["ok"] for c in checks), "checks": checks}
