import hashlib
import re

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Production-grade parameters (OWASP: m=64MiB, t=3, p=2)
hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
# Cheaper parameters used only by the *simulated* attacker-vs-mock-account loops so they finish in milliseconds
sim_hasher = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)

# Local stand-in for a breached-password corpus (stored as SHA-1 like HIBP; we check by 5-char prefix = k-anonymity style)
_BREACHED_PLAIN = ["123456", "password", "qwerty123", "iloveyou", "welcome1", "admin123", "letmein", "Summer2024!", "Passw0rd!",
                   "shopping2023", "Flipkart@123", "abc12345", "monkey123", "dragon2022", "india@123", "Password@1", "sunshine1",
                   "football1", "changeme", "Winter2025!"]
_BREACHED_SHA1 = {hashlib.sha1(p.encode()).hexdigest().upper() for p in _BREACHED_PLAIN}  # noqa: S324 (demo corpus format)
_BREACHED_PREFIXES: dict[str, set[str]] = {}
for _h in _BREACHED_SHA1:
    _BREACHED_PREFIXES.setdefault(_h[:5], set()).add(_h[5:])


def hash_password(pw: str) -> str:
    return hasher.hash(pw)


def verify_password(stored: str, pw: str, h: PasswordHasher = hasher) -> bool:
    try:
        return h.verify(stored, pw)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def is_breached(pw: str) -> bool:
    sha = hashlib.sha1(pw.encode()).hexdigest().upper()  # noqa: S324
    return sha[5:] in _BREACHED_PREFIXES.get(sha[:5], set())


def policy_issues(pw: str) -> list[str]:
    out = []
    if len(pw) < 12:
        out.append("at least 12 characters")
    if not re.search(r"[a-z]", pw) or not re.search(r"[A-Z]", pw):
        out.append("upper and lower case")
    if not re.search(r"\d", pw):
        out.append("a digit")
    if not re.search(r"[^\w\s]", pw):
        out.append("a symbol")
    if is_breached(pw):
        out.append("not found in breach corpus")
    return out
