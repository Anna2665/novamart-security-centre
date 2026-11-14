"""Digital signatures: RSA-PSS(SHA-256) and ECDSA(P-256, SHA-256). Private keys never leave this process."""
import base64
import hashlib
import json
import secrets
import threading
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

ALGS = {"RSA-PSS": "RSA-PSS with SHA-256 (MGF1-SHA256)", "ECDSA-P256": "ECDSA P-256 with SHA-256"}
_PSS = lambda: padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)  # noqa: E731


def canonical(record: Any) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def record_hash(record: Any) -> str:
    return hashlib.sha256(canonical(record)).hexdigest()


def generate(alg: str = "RSA-PSS", bits: int = 2048):
    if alg == "RSA-PSS":
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)
    if alg == "ECDSA-P256":
        return ec.generate_private_key(ec.SECP256R1())
    raise ValueError(f"unsupported algorithm {alg}")


def public_pem(priv) -> str:
    return priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def private_pem(priv) -> bytes:
    return priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def load_private(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


def load_public(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def fingerprint(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def sign(priv, data: bytes) -> bytes:
    if isinstance(priv, rsa.RSAPrivateKey):
        return priv.sign(data, _PSS(), hashes.SHA256())
    return priv.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(pub, data: bytes, signature: bytes) -> bool:
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, data, _PSS(), hashes.SHA256())
        else:
            pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_b64(priv, record: Any) -> str:
    return base64.b64encode(sign(priv, canonical(record))).decode()


def verify_b64(pub, record: Any, sig_b64: str) -> bool:
    try:
        return verify(pub, canonical(record), base64.b64decode(sig_b64))
    except Exception:  # malformed base64 etc.
        return False


# ---- Signature Lab key registry (server memory only) ---------------------------------------------------------------
_LAB: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


def lab_generate(alg: str) -> dict[str, Any]:
    bits = 2048
    priv = generate(alg, bits)
    kid = secrets.token_hex(6)
    with _lock:
        if len(_LAB) >= 25:
            _LAB.pop(next(iter(_LAB)))
        _LAB[kid] = {"priv": priv, "alg": alg, "created": datetime.now(timezone.utc).isoformat()}
    pub = priv.public_key()
    return {"key_id": kid, "algorithm": alg, "algorithm_detail": ALGS[alg], "key_size": bits if alg == "RSA-PSS" else 256,
            "public_key_pem": public_pem(priv), "fingerprint": fingerprint(pub),
            "private_key": {"exposed": False, "location": "backend process memory only", "fingerprint": fingerprint(pub)[:16] + "…"},
            "created": _LAB[kid]["created"]}


def lab_get(key_id: str):
    with _lock:
        if key_id not in _LAB:
            raise KeyError("unknown key id — generate a new key pair")
        return _LAB[key_id]


def lab_sign(key_id: str, record: Any) -> dict[str, Any]:
    k = lab_get(key_id)
    data = canonical(record)
    return {"key_id": key_id, "algorithm": k["alg"], "canonical": data.decode(), "hash": hashlib.sha256(data).hexdigest(),
            "signature": base64.b64encode(sign(k["priv"], data)).decode(), "signed_at": datetime.now(timezone.utc).isoformat()}


def lab_verify(key_id: str, record: Any, signature_b64: str) -> dict[str, Any]:
    k = lab_get(key_id)
    data = canonical(record)
    ok = verify_b64(k["priv"].public_key(), record, signature_b64)
    return {"key_id": key_id, "valid": ok, "hash": hashlib.sha256(data).hexdigest(), "canonical": data.decode(),
            "status": "SIGNATURE VALID — record is authentic and unmodified" if ok
            else "SIGNATURE INVALID — record was modified or not signed by this key"}
