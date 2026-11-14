import base64

import pytest
from cryptography.exceptions import InvalidTag

from app.security import crypto, otp, passwords, pki, signing
from app.sim import rules


def test_aes_gcm_roundtrip_and_nonce_uniqueness():
    k = crypto.derive_key("t")
    n1, c1, t1 = crypto.encrypt(k, b"hello order 42")
    n2, c2, t2 = crypto.encrypt(k, b"hello order 42")
    assert n1 != n2 and c1 != c2
    assert crypto.decrypt(k, n1, c1, t1) == b"hello order 42"
    assert len(n1) == 12 and len(t1) == 16 and len(k) == 32


def test_aes_gcm_wrong_key_and_tamper_detected():
    k = crypto.derive_key("t")
    n, c, t = crypto.encrypt(k, b"secret", b"aad")
    with pytest.raises(InvalidTag):
        crypto.decrypt(b"\x01" * 32, n, c, t, b"aad")
    with pytest.raises(InvalidTag):
        crypto.decrypt(k, n, bytes([c[0] ^ 1]) + c[1:], t, b"aad")
    with pytest.raises(InvalidTag):
        crypto.decrypt(k, n, c, t, b"other-aad")


def test_lab_modes():
    r = crypto.lab_encrypt("Customer: Asha", "customer")
    assert crypto.lab_decrypt(r["blob"], "customer")["verified"] is True
    assert crypto.lab_decrypt(r["blob"], "customer")["plaintext"] == "Customer: Asha"
    assert crypto.lab_decrypt(r["blob"], "customer", "wrong_key")["verified"] is False
    t = crypto.lab_decrypt(r["blob"], "customer", "tampered")
    assert t["verified"] is False and t["flipped_byte"] is not None
    assert "key" not in r and "key_hex" not in r  # key material never leaves the backend


@pytest.mark.parametrize("alg", ["RSA-PSS", "ECDSA-P256"])
def test_signature_sign_verify_tamper(alg):
    k = signing.lab_generate(alg)
    rec = {"order": 7, "amount": 1499}
    s = signing.lab_sign(k["key_id"], rec)
    assert signing.lab_verify(k["key_id"], rec, s["signature"])["valid"]
    assert not signing.lab_verify(k["key_id"], {"order": 7, "amount": 1}, s["signature"])["valid"]
    assert "BEGIN PUBLIC KEY" in k["public_key_pem"] and "PRIVATE" not in str(k)


def test_canonicalisation_is_order_independent():
    assert signing.canonical({"a": 1, "b": 2}) == signing.canonical({"b": 2, "a": 1})


def test_certificate_validation():
    ck, cc = pki.new_ca("CA", "Org")
    _, good = pki.issue(ck, cc, "shop.novamart.demo")
    assert pki.validate(good, cc, "shop.novamart.demo")["valid"]
    assert not pki.validate(good, cc, "other.example")["valid"]
    rk, rc = pki.new_ca("Rogue", "Evil")
    _, bad = pki.issue(rk, rc, "shop.novamart.demo")
    v = pki.validate(bad, cc, "shop.novamart.demo")
    assert not v["valid"] and not v["checks"][0]["ok"] and not v["checks"][1]["ok"]


def test_argon2id_and_breach_check():
    h = passwords.hash_password("Correct#Horse-9")
    assert h.startswith("$argon2id$") and passwords.verify_password(h, "Correct#Horse-9") and not passwords.verify_password(h, "nope")
    assert passwords.is_breached("Summer2024!") and not passwords.is_breached("Zx9#unique-Phrase-77")
    assert passwords.policy_issues("short")


def test_otp_generation_and_hash():
    codes = {otp.generate_otp() for _ in range(200)}
    assert all(len(c) == 6 and c.isdigit() for c in codes) and len(codes) > 150
    h = otp.hash_otp("123456", "cid")
    assert otp.check_otp("123456", "cid", h) and not otp.check_otp("123457", "cid", h) and not otp.check_otp("123456", "other", h)


def test_totp_roundtrip():
    import pyotp
    s = otp.new_totp_secret()
    assert otp.verify_totp(s, pyotp.TOTP(s).now()) and not otp.verify_totp(s, "000000" if pyotp.TOTP(s).now() != "000000" else "111111")


def test_waf_and_validation_rules():
    assert rules.waf_sqli("' OR '1'='1' --") and rules.waf_sqli("x' UNION SELECT 1,2 --") and not rules.waf_sqli("rahul.sharma")
    assert rules.waf_xss("<script>alert(1)</script>") and rules.waf_xss("<img src=x onerror=alert(1)>") and not rules.waf_xss("Great product, 5 stars")
    assert rules.validate_username("arjun.m") and not rules.validate_username("a' OR 1=1 --")
    assert "<script" not in rules.sanitise_html("<script>x</script>hi")
    assert not rules.csp_allows_inline_script(rules.CSP_STRICT) and rules.csp_allows_inline_script(rules.CSP_NONE)


def test_mock_sqli_is_isolated_and_read_only():
    assert rules.mock_login("' OR '1'='1' --", "x", "unsafe")["row_count"] == len(rules.MOCK_USERS)
    assert rules.mock_login("' OR '1'='1' --", "x", "parameterised")["row_count"] == 0
    assert rules.mock_login("admin'; DROP TABLE users; --", "x", "unsafe")["error"]  # stacked statements refused


def test_entropy_rises_when_encrypted():
    plain = b"order,1234,Pune,NovaMart demo record\n" * 50
    assert rules.entropy(plain) < 5 and rules.entropy(crypto.seal(b"k" * 32, plain)) > 7.5
