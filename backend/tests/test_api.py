import time

import pytest

from app.sim import engine
from app.sim.defences import IDS
from app.sim.scenarios import SCENARIOS
from tests.conftest import login


def wait_idle(client, headers, timeout=40):
    t = time.time()
    while time.time() - t < timeout:
        if not client.get("/api/sim/state", headers=headers).json()["running"]:
            return
        time.sleep(0.2)
    raise AssertionError("simulation did not finish")


# ---- authentication -------------------------------------------------------------------------------------------------
def test_health_and_auth_required(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/api/sim/state").status_code == 401


def test_login_requires_otp_then_grants_access(client):
    from app.deps import login_limiter
    login_limiter.reset()
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Admin#Test-2026x"})
    j = r.json()
    assert r.status_code == 200 and "token" not in j and j["delivery"]["status"] == "dev_echo" and j["delivery"]["dev_mode"]
    assert len(j["delivery"]["dev_otp"]) == 6 and j["email_masked"].endswith("@gmail.com")
    wrong = "000000" if j["delivery"]["dev_otp"] != "000000" else "111111"
    bad = client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": wrong})
    assert bad.status_code == 401 and bad.json()["attempts_left"] == 2
    ok = client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": j["delivery"]["dev_otp"]})
    assert ok.status_code == 200 and ok.json()["token"]
    reuse = client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": j["delivery"]["dev_otp"]})
    assert reuse.status_code == 400  # a consumed challenge cannot be replayed


def test_otp_attempt_limit_and_resend_invalidates_old_code(client):
    from app.deps import login_limiter
    login_limiter.reset()
    j = client.post("/api/auth/login", json={"username": "viewer", "password": "Viewer#Test-2026x"}).json()
    old = j["delivery"]["dev_otp"]
    r = client.post("/api/auth/otp/resend", json={"challenge_id": j["challenge_id"]})
    assert r.status_code == 429  # cooldown
    from app.config import settings
    from app.db import session_scope
    from app.models import OtpChallenge
    from datetime import datetime, timedelta, timezone
    with session_scope() as db:
        db.get(OtpChallenge, j["challenge_id"]).last_sent_at = datetime.now(timezone.utc) - timedelta(seconds=settings.otp_resend_cooldown + 1)
    r = client.post("/api/auth/otp/resend", json={"challenge_id": j["challenge_id"]})
    assert r.status_code == 200
    new = r.json()["delivery"]["dev_otp"]
    if new != old:
        assert client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": old}).status_code == 401
    codes = ["000000", "111111", "222222"]
    codes = [c for c in codes if c != new][:3]
    last = None
    for c in codes + ["333333"]:
        last = client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": c})
    assert last.status_code in (429, 400)  # attempts exhausted → challenge dead
    assert client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": new}).status_code in (400, 429)


def test_otp_expiry(client):
    from app.deps import login_limiter
    from app.db import session_scope
    from app.models import OtpChallenge
    from datetime import datetime, timedelta, timezone
    login_limiter.reset()
    j = client.post("/api/auth/login", json={"username": "viewer", "password": "Viewer#Test-2026x"}).json()
    with session_scope() as db:
        db.get(OtpChallenge, j["challenge_id"]).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    r = client.post("/api/auth/otp/verify", json={"challenge_id": j["challenge_id"], "code": j["delivery"]["dev_otp"]})
    assert r.status_code == 410


def test_wrong_password_lockout(client):
    from app.deps import login_limiter
    from app.db import session_scope
    from app.models import User
    from sqlalchemy import select
    for _ in range(5):
        login_limiter.reset()
        r = client.post("/api/auth/login", json={"username": "viewer", "password": "bad-password"})
        assert r.status_code in (401, 423)
    login_limiter.reset()
    r = client.post("/api/auth/login", json={"username": "viewer", "password": "Viewer#Test-2026x"})
    assert r.status_code == 423  # correct password is refused while locked
    with session_scope() as db:
        u = db.scalar(select(User).where(User.username == "viewer"))
        u.locked_until, u.failed_attempts = None, 0


def test_login_rate_limit(client):
    from app.deps import login_limiter
    login_limiter.reset()
    codes = [client.post("/api/auth/login", json={"username": "nobody", "password": "x"}).status_code for _ in range(20)]
    assert 429 in codes
    login_limiter.reset()


def test_forged_and_tampered_tokens_rejected(client, admin):
    import base64, json
    h, p, s = admin["Authorization"].split()[1].split(".")
    claims = json.loads(base64.urlsafe_b64decode(p + "=="))
    claims["role"] = "admin"
    forged = h + "." + base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode() + "." + s[:-2] + "AA"
    assert client.get("/api/sim/state", headers={"Authorization": "Bearer " + forged}).status_code == 401


def test_rbac_enforced(client, viewer, analyst, admin):
    assert client.post("/api/sim/run", json={"scenario_id": "sqli"}, headers=viewer).status_code == 403
    assert client.post("/api/db/tamper", json={}, headers=analyst).status_code == 403
    assert client.get("/api/auth/users", headers=analyst).status_code == 403
    assert client.get("/api/auth/users", headers=admin).status_code == 200
    cust = client.get("/api/db/customers", headers=viewer).json()
    assert cust["pii_revealed"] is False and "•" in cust["rows"][0]["email"]
    cust = client.get("/api/db/customers", headers=admin).json()
    assert cust["pii_revealed"] is True and "@" in cust["rows"][0]["email"] and "•" not in cust["rows"][0]["email"]


def test_totp_enrolment_flow(client, admin):
    import pyotp
    e = client.post("/api/auth/totp/enroll", headers=admin).json()
    assert e["uri"].startswith("otpauth://totp/")
    assert client.post("/api/auth/totp/confirm", json={"code": "000000"}, headers=admin).status_code in (400, 200)
    assert client.post("/api/auth/totp/confirm", json={"code": pyotp.TOTP(e["secret"]).now()}, headers=admin).status_code == 200
    from app.deps import login_limiter
    login_limiter.reset()
    j = client.post("/api/auth/login", json={"username": "admin", "password": "Admin#Test-2026x"}).json()
    assert "totp" in j["methods"]
    r = client.post("/api/auth/totp/verify", json={"challenge_id": j["challenge_id"], "code": pyotp.TOTP(e["secret"]).now()})
    assert r.status_code == 200
    assert client.post("/api/auth/totp/disable", json={"code": pyotp.TOTP(e["secret"]).now()}, headers=admin).status_code == 200


# ---- crypto & signature APIs ---------------------------------------------------------------------------------------------
def test_crypto_api(client, admin):
    s = client.get("/api/crypto/samples", headers=admin).json()
    enc = client.post("/api/crypto/aes/encrypt", json={"plaintext": s["customer"], "dataset": "customer"}, headers=admin).json()
    assert enc["algorithm"] == "AES-256-GCM" and len(enc["nonce_hex"]) == 24 and len(enc["tag_hex"]) == 32
    ok = client.post("/api/crypto/aes/decrypt", json={"blob": enc["blob"], "dataset": "customer"}, headers=admin).json()
    assert ok["verified"] and ok["plaintext"] == s["customer"]
    for mode in ("wrong_key", "tampered"):
        bad = client.post("/api/crypto/aes/decrypt", json={"blob": enc["blob"], "dataset": "customer", "mode": mode}, headers=admin).json()
        assert bad["verified"] is False and bad["plaintext"] is None
    assert client.get("/api/crypto/algorithms", headers=admin).json()["algorithms"][-1]["status"] == "broken"


def test_signature_api_flow_triggers_integrity_alert(client, admin):
    k = client.post("/api/sig/keys", json={"algorithm": "RSA-PSS"}, headers=admin).json()
    rec = client.get("/api/sig/samples", headers=admin).json()["order"]
    sg = client.post("/api/sig/sign", json={"key_id": k["key_id"], "record": rec}, headers=admin).json()
    assert client.post("/api/sig/verify", json={"key_id": k["key_id"], "record": rec, "signature": sg["signature"]}, headers=admin).json()["valid"]
    rec2 = {**rec, "amount": 1}
    bad = client.post("/api/sig/verify", json={"key_id": k["key_id"], "record": rec2, "signature": sg["signature"]}, headers=admin).json()
    assert bad["valid"] is False and bad["alert"]["attack_type"] == "integrity_violation" and bad["alert"]["simulated"] is False
    issue = client.post("/api/sig/pki/issue", json={"issuer": "rogue"}, headers=admin).json()
    assert issue["validation"]["valid"] is False


# ---- database tamper → detect → restore ------------------------------------------------------------------------------------
def test_db_tamper_detection_and_restore(client, admin):
    assert client.get("/api/db/integrity", headers=admin).json()["tampered"] == []
    t = client.post("/api/db/tamper", json={"product_id": 1, "new_price": 1}, headers=admin).json()
    assert t["before"]["price"] == 1499 and t["after"]["current"]["price"] == 1
    assert not t["after"]["hash_ok"] and not t["after"]["sig_ok"]
    scan = client.get("/api/db/integrity", headers=admin).json()
    assert len(scan["tampered"]) == 1 and scan["tampered"][0]["trusted"]["price"] == 1499
    r = client.post("/api/db/restore", json={"entity": "product", "id": 1}, headers=admin).json()
    assert r["verified"] and r["restored_from"]["price"] == 1499
    assert client.get("/api/db/integrity", headers=admin).json()["tampered"] == []


def test_smart_attacker_rewrites_hash_but_signature_still_fails(client, admin):
    t = client.post("/api/db/tamper", json={"product_id": 2, "new_price": 5, "recompute_hash": True}, headers=admin).json()
    assert t["after"]["hash_ok"] is True and t["after"]["sig_ok"] is False
    client.post("/api/db/restore", json={"entity": "product", "id": 2}, headers=admin)
    assert client.get("/api/db/integrity", headers=admin).json()["tampered"] == []


def test_sqli_lab_modes(client, admin):
    j = lambda mode: client.post("/api/db/sqli", json={"username": "' OR '1'='1' --", "password": "x", "mode": mode}, headers=admin).json()  # noqa: E731
    assert j("unsafe")["row_count"] >= 5 and j("parameterised")["row_count"] == 0
    w = j("waf")
    assert w["waf"]["blocked"] and w["row_count"] == 0


# ---- the 12 scenarios -----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("scen", [s.id for s in SCENARIOS])
def test_scenario_outcome_depends_on_defences(scen):
    on, off = {d: True for d in IDS}, {d: False for d in IDS}
    a, b = engine.build_run(scen, on, True), engine.build_run(scen, off, True)
    assert a["result"] in ("blocked", "contained") and b["result"] == "breach"
    assert a["detected"] and b["impact"]["C"] + b["impact"]["I"] + b["impact"]["A"] > a["impact"]["C"] + a["impact"]["I"] + a["impact"]["A"]
    assert any(c["outcome"] == "blocked" for st in a["stages"] for c in st["checks"]) or a["result"] == "contained" or scen == "ddos"
    assert all(c["outcome"] == "inactive" for st in b["stages"] for c in st["checks"])  # OFF means not evaluated
    assert [s["status"] for s in a["stages"]].count("active") == 0


def test_individual_defences_change_the_outcome():
    only = lambda *ids: {d: d in ids for d in IDS}  # noqa: E731
    r = lambda s, *ids: engine.build_run(s, only(*ids), True)  # noqa: E731
    assert r("sqli", "waf")["result"] == "blocked" and r("sqli", "waf")["stages"][1]["status"] == "blocked"
    assert r("sqli", "sqli_protection")["stages"][3]["status"] == "blocked"
    assert r("sqli", "input_validation")["stages"][2]["status"] == "blocked"
    assert r("sqli", "ids")["result"] == "breach" and r("sqli", "ids")["detected"]  # detection without prevention
    assert r("brute_force", "mfa")["stages"][2]["status"] == "blocked"
    assert r("brute_force", "rate_limiting")["stages"][1]["status"] == "blocked"
    assert r("brute_force", "waf")["result"] == "blocked"
    assert r("ddos", "cdn", "rate_limiting")["result"] == "blocked"
    assert r("ddos", "cdn")["result"] == "breach" and r("ddos", "cdn", "waf")["result"] == "contained"
    assert r("db_tamper", "db_integrity")["result"] == "contained" and r("db_tamper", "digital_signatures")["result"] == "contained"
    assert r("db_tamper")["result"] == "breach"
    assert r("exfiltration", "encryption_at_rest")["result"] == "contained"
    assert r("priv_esc", "rbac")["result"] == "blocked" and r("mitm", "tls")["result"] == "blocked"
    assert r("cred_stuffing", "rate_limiting")["result"] == "contained"
    assert r("ransomware", "edr")["result"] == "contained" and r("ransomware", "network_segmentation")["result"] == "blocked"


def test_run_scenario_end_to_end_with_incident_lifecycle(client, admin):
    client.post("/api/sim/mode", json={"enabled": False}, headers=admin)
    client.post("/api/sim/reset", headers=admin)
    client.post("/api/sim/mode", json={"enabled": False}, headers=admin)
    res = client.post("/api/sim/run", json={"scenario_id": "db_tamper"}, headers=admin)
    assert res.status_code == 200 and res.json()["result"] == "breach"
    assert client.post("/api/sim/run", json={"scenario_id": "sqli"}, headers=admin).status_code == 409  # one at a time
    wait_idle(client, admin)
    assert client.get("/api/db/integrity", headers=admin).json()["tampered"], "real DB record must actually be modified"
    st = client.get("/api/sim/state", headers=admin).json()
    assert st["nodes"]["db"]["status"] == "compromised" and st["cia"]["I"] < st["cia"]["baseline"]["I"]
    incs = client.get("/api/incidents", headers=admin).json()
    inc = incs[0]
    assert inc["severity"] in ("high", "critical") and inc["phase_name"] in ("Preparation", "Identification")
    # cannot skip phases
    assert client.post(f"/api/incidents/{inc['id']}/advance", headers=admin).status_code == 409
    for _ in range(12):
        inc = client.get(f"/api/incidents/{inc['id']}", headers=admin).json()
        if inc["status"] == "resolved":
            break
        for t in [t for t in inc["checklist"] if t["phase"] == inc["phase"] and not t["done"]]:
            r = client.post(f"/api/incidents/{inc['id']}/tasks/{t['id']}/toggle", headers=admin)
            assert r.status_code == 200, r.text
        if inc["phase"] == 5:
            client.put(f"/api/incidents/{inc['id']}/notes", json={"text": "Root cause: write access without integrity gate."}, headers=admin)
        client.post(f"/api/incidents/{inc['id']}/advance", headers=admin)
    final = client.get(f"/api/incidents/{inc['id']}", headers=admin).json()
    assert final["status"] == "resolved" and len(final["audit"]) > 5
    assert client.get("/api/db/integrity", headers=admin).json()["tampered"] == [], "restore_db task must repair the record"
    st = client.get("/api/sim/state", headers=admin).json()
    assert st["nodes"]["db"]["status"] == "healthy" and st["cia"]["I"] >= st["cia"]["baseline"]["I"] - 0.1
    client.post("/api/sim/mode", json={"enabled": True}, headers=admin)


def test_defences_on_blocks_and_counts(client, admin):
    client.post("/api/sim/mode", json={"enabled": True}, headers=admin)
    before = client.get("/api/metrics", headers=admin).json()["counters"]
    r = client.post("/api/sim/run", json={"scenario_id": "sqli"}, headers=admin).json()
    assert r["result"] == "blocked"
    wait_idle(client, admin)
    after = client.get("/api/metrics", headers=admin).json()["counters"]
    assert after["total_attacks"] == before["total_attacks"] + 1 and after["blocked"] == before["blocked"] + 1
    cia = client.get("/api/cia", headers=admin).json()
    assert not [i for i in cia["impacts"] if i["run_id"] == r["run_id"]], "a blocked attack must not leave unresolved damage"
    assert r["impact"] == {"C": 0.0, "I": 0.0, "A": 0.0}, "a blocked attack must report zero CIA impact"
    assert any(e["run_id"] == r["run_id"] for e in client.get("/api/events", headers=admin).json())


def test_compare_has_no_side_effects(client, admin):
    before = client.get("/api/metrics", headers=admin).json()["counters"]["total_attacks"]
    c = client.post("/api/sim/compare", json={"scenario_id": "ransomware"}, headers=admin).json()
    assert c["off"]["result"] == "breach" and c["on"]["result"] in ("blocked", "contained")
    assert client.get("/api/metrics", headers=admin).json()["counters"]["total_attacks"] == before
    assert client.get("/api/backup", headers=admin).json()["volume"]["state"] == "healthy"


# ---- backup & recovery ----------------------------------------------------------------------------------------------------------
def test_backup_ransomware_recovery_and_poisoning(client, admin):
    b = client.post("/api/backup/create", json={"label": "test"}, headers=admin).json()
    assert b["status"] == "verified" and all(b["checks"].values())
    client.post("/api/backup/ransomware", headers=admin)
    assert client.get("/api/backup", headers=admin).json()["volume"]["state"] == "encrypted"
    assert client.post("/api/backup/create", json={"label": "x"}, headers=admin).status_code == 409  # never back up ciphertext
    bad = client.post(f"/api/backup/{b['id']}/corrupt", headers=admin).json()
    assert bad["status"] == "corrupt"
    # newest verified backup (the seeded baseline) is still usable; the poisoned one is refused
    assert client.post("/api/backup/restore", json={"backup_id": b["id"]}, headers=admin).status_code == 409
    r = client.post("/api/backup/restore", json={}, headers=admin)
    assert r.status_code == 200 and r.json()["after"] == "healthy"
    vol = client.get("/api/backup", headers=admin).json()["volume"]
    assert vol["encrypted"] == 0 and all(f["entropy"] < 6 for f in vol["files"])


def test_ransomware_run_recovers_with_secure_backups(client, admin):
    client.post("/api/sim/mode", json={"enabled": True}, headers=admin)
    client.put("/api/sim/defences/network_segmentation", json={"enabled": False}, headers=admin)
    client.put("/api/sim/defences/edr", json={"enabled": False}, headers=admin)
    r = client.post("/api/sim/run", json={"scenario_id": "ransomware"}, headers=admin).json()
    assert r["result"] == "contained" and r["metrics"]["files_encrypted"] == r["metrics"]["files_total"]
    wait_idle(client, admin)
    assert client.get("/api/backup", headers=admin).json()["volume"]["state"] == "healthy"
    client.put("/api/sim/defences/secure_backups", json={"enabled": False}, headers=admin)
    r = client.post("/api/sim/run", json={"scenario_id": "ransomware"}, headers=admin).json()
    assert r["result"] == "breach"
    wait_idle(client, admin)
    assert client.get("/api/backup", headers=admin).json()["volume"]["state"] == "encrypted"
    client.post("/api/sim/reset", headers=admin)


# ---- audit chain -------------------------------------------------------------------------------------------------------------------
def test_audit_chain_detects_edits(client, admin):
    v = client.get("/api/audit/verify", headers=admin).json()
    assert v["valid"] and v["checked"] > 10
    from app.db import session_scope
    from app.models import AuditLog
    with session_scope() as db:
        row = db.get(AuditLog, max(1, v["checked"] // 2))
        original = dict(row.detail)
        row.detail = {**original, "tampered": True}
    bad = client.get("/api/audit/verify", headers=admin).json()
    assert not bad["valid"] and bad["first_bad_id"]
    with session_scope() as db:
        db.get(AuditLog, bad["first_bad_id"]).detail = original
    assert client.get("/api/audit/verify", headers=admin).json()["valid"]


def test_websocket_requires_token_and_streams(client, admin):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/ws?token=bad"):
            pass
    with client.websocket_connect("/api/ws?token=" + admin["Authorization"].split()[1]) as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello" and "nodes" in hello["data"]["state"]


def test_metrics_cia_intel_endpoints(client, admin):
    m = client.get("/api/metrics", headers=admin).json()
    assert m["counters"]["total_attacks"] > 200 and len(m["trend"]) > 10 and m["total_nodes"] == 14
    c = client.get("/api/cia", headers=admin).json()
    assert set(c["scores"]) >= {"C", "I", "A"} and c["signals"]["I"]
    i = client.get("/api/intel/overview", headers=admin).json()
    assert len(i["risk_matrix"]) == 12 and i["iocs"][0]["simulated"]
    assert len(client.get("/api/sim/scenarios", headers=admin).json()) == 12 and len(client.get("/api/sim/defences", headers=admin).json()["defences"]) == 21
