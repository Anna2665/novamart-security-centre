"""AES-256-GCM service. Keys live only on the backend; the API never returns key material."""
import base64
import hashlib
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .secrets_store import master_key

NONCE_LEN = 12
TAG_LEN = 16


def derive_key(purpose: str) -> bytes:
    """Purpose-bound 256-bit data key derived from the master key (HKDF-SHA256)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"cyberguard/{purpose}".encode()).derive(master_key())


def key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(NONCE_LEN)  # fresh random 96-bit nonce per message
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, sealed[:-TAG_LEN], sealed[-TAG_LEN:]


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes | None = None) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)


def seal(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    n, c, t = encrypt(key, plaintext, aad)
    return n + c + t


def unseal(key: bytes, blob: bytes, aad: bytes | None = None) -> bytes:
    return decrypt(key, blob[:NONCE_LEN], blob[NONCE_LEN:-TAG_LEN], blob[-TAG_LEN:], aad)


def seal_text(purpose: str, text: str, aad: str = "") -> str:
    return base64.urlsafe_b64encode(seal(derive_key(purpose), text.encode(), aad.encode() or None)).decode()


def unseal_text(purpose: str, token: str, aad: str = "") -> str:
    return unseal(derive_key(purpose), base64.urlsafe_b64decode(token.encode()), aad.encode() or None).decode()


# ---- Cryptography Lab -------------------------------------------------------------------------------------------

def lab_encrypt(plaintext: str, dataset: str) -> dict[str, Any]:
    key = derive_key("lab")
    aad = f"cyberguard-lab:{dataset}".encode()
    nonce, ct, tag = encrypt(key, plaintext.encode(), aad)
    blob = nonce + ct + tag
    return {
        "algorithm": "AES-256-GCM",
        "key_id": key_id(key),
        "key_bits": 256,
        "aad": aad.decode(),
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ct.hex(),
        "tag_hex": tag.hex(),
        "blob": base64.b64encode(blob).decode(),
        "plaintext_bytes": len(plaintext.encode()),
    }


def lab_decrypt(blob_b64: str, dataset: str, mode: str = "correct") -> dict[str, Any]:
    """mode: correct | wrong_key | tampered. Always reports the authentication-tag verification result."""
    blob = bytearray(base64.b64decode(blob_b64))
    nonce, ct, tag = bytes(blob[:NONCE_LEN]), bytearray(blob[NONCE_LEN:-TAG_LEN]), bytes(blob[-TAG_LEN:])
    aad = f"cyberguard-lab:{dataset}".encode()
    key = derive_key("lab")
    note, flipped = "Correct key, untouched ciphertext.", None
    if mode == "wrong_key":
        key = os.urandom(32)
        note = "Decrypting with a random, different 256-bit key."
    elif mode == "tampered" and ct:
        flipped = len(ct) // 2
        ct[flipped] ^= 0x01
        note = f"One bit flipped in ciphertext byte {flipped} (an attacker modifying data in transit)."
    out: dict[str, Any] = {"mode": mode, "note": note, "tag_hex": tag.hex(), "nonce_hex": nonce.hex(),
                           "ciphertext_hex": bytes(ct).hex(), "flipped_byte": flipped, "key_id": key_id(key)}
    try:
        pt = decrypt(key, nonce, bytes(ct), tag, aad)
        out.update(verified=True, plaintext=pt.decode(errors="replace"), status="Authentication tag VERIFIED — plaintext restored")
    except InvalidTag:
        out.update(verified=False, plaintext=None,
                   status="Authentication tag MISMATCH — decryption refused (GCM detected wrong key or modified data)")
    return out


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def bit_difference(a_hex: str, b_hex: str) -> int:
    return bin(int(a_hex, 16) ^ int(b_hex, 16)).count("1")


ALGORITHMS = [
    {"id": "aes-256-gcm", "name": "AES-256-GCM", "type": "Symmetric AEAD cipher", "key_bits": 256, "security_bits": 256,
     "purpose": "Encrypt data at rest and in transit; the GCM tag also proves the data was not modified (confidentiality + integrity).",
     "limits": "Nonce must never repeat with the same key; key distribution is the hard part.", "status": "recommended"},
    {"id": "rsa", "name": "RSA (2048/3072-bit)", "type": "Asymmetric", "key_bits": 3072, "security_bits": 128,
     "purpose": "Digital signatures (RSA-PSS), key exchange and certificates. Slow, so it protects keys and hashes, not bulk data.",
     "limits": "Vulnerable to future quantum computers; 1024-bit and below is broken; use PSS/OAEP padding only.", "status": "recommended"},
    {"id": "sha-256", "name": "SHA-256", "type": "Cryptographic hash", "key_bits": 0, "security_bits": 128,
     "purpose": "Integrity fingerprint for records, passwords (inside a KDF), certificates and signatures.",
     "limits": "Not encryption. Never use a bare hash for passwords — use Argon2id.", "status": "recommended"},
    {"id": "3des", "name": "3DES (Triple DES)", "type": "Symmetric block cipher", "key_bits": 168, "security_bits": 112,
     "purpose": "Legacy payment and banking systems.",
     "limits": "64-bit blocks: the Sweet32 attack recovers data after ~2^32 blocks. Deprecated by NIST. Do not use.", "status": "deprecated"},
    {"id": "des", "name": "DES", "type": "Symmetric block cipher", "key_bits": 56, "security_bits": 56,
     "purpose": "Historic standard (1977).",
     "limits": "56-bit key is brute-forced in hours with commodity hardware. Broken. Do not use.", "status": "broken"},
]


def brute_force_estimate(security_bits: int, guesses_per_second: float = 1e12) -> dict[str, Any]:
    seconds = (2 ** security_bits) / guesses_per_second / 2
    return {"security_bits": security_bits, "guesses_per_second": guesses_per_second, "avg_seconds": seconds,
            "human": _human(seconds)}


def _human(s: float) -> str:
    for unit, div in (("years", 31_557_600), ("days", 86_400), ("hours", 3600), ("minutes", 60), ("seconds", 1)):
        if s >= div:
            v = s / div
            return f"{v:,.0f} {unit}" if v < 1e6 else f"{v:.2e} {unit}"
    return "< 1 second"
