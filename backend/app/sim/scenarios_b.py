"""Scenarios 7-12."""
import base64
import json
import os
import secrets

import jwt

from ..security import crypto, pki, rbac, tokens
from ..services import backup, dbsec
from . import rules
from .ctx import Ctx, Scenario, code, compare, kv, series, table
from .scenarios_a import _s


# 7 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def run_phishing(c: Ctx) -> None:
    mail = {"from": "support@n0vamart-secure.co", "spf": "fail", "dkim": "none", "dmarc": "fail", "link": "https://novamart-verify.co/login",
            "link_text_host": "novamart.com", "body": "URGENT: your account will be suspended. Verify your password within 24 hours."}
    score = rules.phish_score(mail)
    c.stage(0)
    c.log("warn", "Attacker sends a spoofed 'account suspended' email to a staff member")
    c.evidence(table("Email header & content analysis", ["Indicator", "Flagged", "Points", "Detail"],
                     [[r["indicator"], "YES" if r["flagged"] else "no", r["points"], r["detail"]] for r in score["indicators"]]))
    c.evidence(kv("Verdict", [["Phishing score", f"{score['score']} / 100"], ["Quarantine threshold", score["threshold"]]]))
    if c.guard("email_security", score["score"] >= score["threshold"], "Score below threshold — delivered",
               f"Score {score['score']} ≥ {score['threshold']}: look-alike domain, SPF/DKIM/DMARC failure → email quarantined, warning banner shown", node="portal"):
        c.conclude("blocked", f"Email security scored the message {score['score']}/100 and quarantined it before the user saw it.")
        return
    c.stage(1)
    c.log("warn", "Employee clicks the link and lands on a pixel-perfect fake login page")
    c.evidence(compare("Link comparison", {"title": "Real site", "tone": "ok", "code": "https://shop.novamart.demo/login"},
                       {"title": "Phishing site", "tone": "danger", "code": mail["link"]}))
    c.stage(2)
    c.hit("portal")
    c.log("crit", "Fake page captures username and password (fictional: rhea.kapoor / ••••••••••)")
    c.stage(3)
    c.log("warn", "Attacker replays the stolen password against the real login")
    if c.guard("mfa", True, "", "Password accepted, but the 6-digit email OTP is required — attacker cannot read the victim's mailbox; login denied", node="auth"):
        c.conclude("blocked", "The password was stolen, but MFA stopped the login: the OTP never reaches the attacker.")
        return
    c.stage(4)
    c.hit("auth")
    c.hit("app")
    c.log("crit", "Attacker is signed in as the victim")
    c.conclude("breach", "Credentials phished and replayed: attacker signed in as a legitimate user.")


# 8 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def run_ddos(c: Ctx) -> None:
    legit, cap, peak = 900, 6000, 120000
    cdn, rl, waf = (0.12 if c.on("cdn") else 1.0), (0.15 if c.on("rate_limiting") else 1.0), (0.6 if c.on("waf") else 1.0)
    c.stage(0)
    c.log("warn", "Botnet of 48,000 simulated devices assembled; flood target: customer portal")
    c.stage(1)
    xs, inc, flt, av = [], [], [], []
    for t in range(0, 61, 3):
        atk = peak * min(1, t / 12) if t <= 48 else peak * max(0, (60 - t) / 12)
        passed = atk * cdn * rl * waf
        xs.append(f"{t}s")
        inc.append(round(atk + legit))
        flt.append(round(passed + legit))
        av.append(round(min(1, cap / (passed + legit)) * 100, 1))
    for d, f, txt in (("cdn", cdn, "CDN scrubbing absorbed {p:.0f}% of attack traffic at the edge"),
                      ("rate_limiting", rl, "Per-IP token buckets dropped {p:.0f}% of the remaining flood"),
                      ("waf", waf, "WAF bot rules dropped {p:.0f}% of the remaining requests")):
        if c.on(d):
            c.check(d, "throttled", txt.format(p=(1 - f) * 100))
            c.log("success", txt.format(p=(1 - f) * 100))
        else:
            c.check(d, "inactive", f"{d} is OFF — rule not evaluated")
    c.evidence(series("Traffic and availability over 60 s", xs, [{"name": "Incoming req/s", "values": inc}, {"name": "Reaching origin req/s", "values": flt},
                                                                  {"name": "Server capacity", "values": [cap] * len(xs)}], "req/s"))
    c.stage(2)
    peak_load = max(flt) / cap
    min_av = min(av)
    c.log("info" if peak_load < 0.9 else "crit", f"Origin peak load: {max(flt):,} req/s vs capacity {cap:,} req/s ({peak_load * 100:.0f}%)")
    c.evidence(series("Service availability (%)", xs, [{"name": "Availability", "values": av}], "%"))
    c.stage(3)
    c.metrics.update(peak_rps=max(inc), origin_peak_rps=max(flt), min_availability=min_av)
    if min_av >= 95:
        c.protect("waf")
        c.log("success", f"Portal stayed up — minimum availability {min_av}%")
        c.conclude("blocked", f"Flood mitigated: minimum availability {min_av}% — customers did not notice.")
    elif min_av >= 50:
        c.degrade("portal")
        c.log("warn", f"Portal degraded — minimum availability {min_av}%")
        c.conclude("contained", f"Partial mitigation: portal degraded to {min_av}% availability at peak.", 0.45)
    else:
        c.degrade("portal")
        c.degrade("app")
        c.log("crit", f"Portal down — minimum availability {min_av}%; customers cannot shop")
        c.conclude("breach", f"Service outage: availability fell to {min_av}% (no effective traffic filtering).")


# 9 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def run_ransomware(c: Ctx) -> None:
    vol = backup.volume
    if not c.dry:
        backup.ensure_verified_backup("system")
    files = dict(vol.files) if c.dry else vol.files
    c.stage(0)
    c.log("warn", "Assumed breach: attacker controls an admin workstation (malicious attachment, zero-day loader — no signature yet)")
    c.stage(1)
    src, dst = "Management", "Data"
    c.log("info", f"Ransomware tries to reach the database from the {src} zone")
    if c.guard("network_segmentation", not rbac.zone_allowed(src, dst), "Zone policy permits the flow",
               f"Zone policy: {src} → {dst} is DENY (deny-by-default). Admin workstation cannot reach the database or storage", node="firewall"):
        c.conclude("blocked", "Network segmentation kept the ransomware on one workstation: the data zone was unreachable.")
        return
    c.stage(2)
    c.log("crit", "Encryption routine starts on the application & data servers (sandbox volume of fictional files)")
    key = os.urandom(32)
    rows, enc, suspicious, killed = [], [], 0, None
    for i, path in enumerate(sorted(files), 1):
        e0 = rules.entropy(files[path])
        files[path] = crypto.seal(key, files[path], b"sandbox")
        e1 = rules.entropy(files[path])
        enc.append(path)
        rows.append([path, f"{e0:.2f}", f"{e1:.2f}", "ENCRYPTED"])
        if e1 - e0 > 2.5:
            suspicious += 1
        if c.on("edr") and suspicious >= 8:
            killed = i
            break
    if not c.dry:
        vol.encrypted.update(enc)
    c.hit("db")
    c.hit("cloud")
    c.evidence(table("File entropy before → after encryption (bits/byte)", ["File", "Before", "After", "State"], rows[:14] + ([["…", "", "", f"{len(rows) - 14} more"]] if len(rows) > 14 else [])))
    c.metrics.update(files_encrypted=len(enc), files_total=len(files))
    if c.guard("edr", killed is not None, "No behavioural rule triggered",
               f"EDR rule 'mass high-entropy writes': {suspicious} files jumped >2.5 bits/byte entropy → process killed, host isolated after {killed} files", node="app"):
        c.isolate("app")
        c.log("success", f"EDR terminated the encryptor after {killed} of {len(files)} files and isolated the host")
    else:
        c.log("crit", f"{len(enc)} of {len(files)} files encrypted — ransom note dropped: 'Pay 2 BTC' (fictional)")
    c.stage(3)
    c.log("info", "Recovery: restore from the isolated backup vault")
    if c.on("secure_backups"):
        try:
            if c.dry:
                ok = True
            else:
                backup.restore(None, "recovery")
                ok = True
        except ValueError as e:
            ok = False
            c.check("secure_backups", "failed", str(e))
            c.log("crit", str(e))
        if ok:
            c.check("secure_backups", "recovered", "Latest backup verified (decrypt ✔ hash ✔ RSA-PSS signature ✔) and restored — no ransom paid", "Secure backups")
            c.heal("db")
            c.heal("cloud")
            c.heal("app")
            c.log("success", "Verified clean backup restored — files readable again")
            c.conclude("contained", f"{'EDR limited the damage and ' if killed else ''}the verified backup restored all files without paying a ransom.", 0.3 if killed else 0.5)
            return
    else:
        c.check("secure_backups", "inactive", "Secure backups are OFF — no verified copy to restore")
    if killed:
        c.conclude("contained", f"EDR stopped the encryptor after {killed} files; {killed} files stay encrypted until restored from backup.", 0.4)
    else:
        c.log("crit", "No usable backup — operations halted")
        c.conclude("breach", f"All {len(enc)} files encrypted and no clean backup available: business halted.")


# 10 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _b64(d: bytes) -> str: return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
def _unb64(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def run_priv_esc(c: Ctx) -> None:
    token = tokens.issue("attacker.customer", "viewer", minutes=5)
    h, p, sig = token.split(".")
    legit = json.loads(_unb64(p))
    forged_claims = {**legit, "role": "admin", "scope": "*"}
    forged = f"{h}.{_b64(json.dumps(forged_claims, separators=(',', ':')).encode())}.{sig}"
    c.stage(0)
    c.log("info", "Attacker signs up as an ordinary customer (role: viewer) and receives a valid signed JWT")
    c.evidence(kv("Legitimate token claims", [[k, v] for k, v in legit.items() if k in ("sub", "role", "exp")]))
    c.stage(1)
    c.log("warn", "Attacker edits the token payload: role viewer → admin, scope → *, keeping the original signature")
    c.evidence(compare("Token claims", {"title": "Issued by server", "tone": "ok", "items": [["role", legit["role"]], ["signature", "valid HS256"]]},
                       {"title": "Forged by attacker", "tone": "danger", "items": [["role", "admin"], ["scope", "*"], ["signature", "copied from original (now invalid)"]]}))
    c.stage(2)
    c.log("info", "Forged token is sent to the admin API")
    rejected, err = False, ""
    try:
        tokens.decode(forged)
    except jwt.PyJWTError as e:
        rejected, err = True, f"{type(e).__name__}: {e}"
    accepted_claims = jwt.decode(forged, options={"verify_signature": False})  # what a misconfigured server would do
    c.evidence(kv("Server-side token verification", [["Verification enabled", "YES" if c.on("rbac") else "NO (vulnerable configuration)"],
                                                      ["Result with verification", err or "accepted"], ["Role the server would act on", "viewer (token rejected)" if c.on("rbac") else accepted_claims["role"]]]))
    if c.guard("rbac", rejected, "Token verified", f"Signature check failed ({err}) → 401, token rejected", node="admin"):
        c.conclude("blocked", "Signed-token verification rejected the forged admin claim: any edit breaks the HMAC signature.")
        return
    c.log("crit", "Server trusts the claims without verifying the signature → role=admin accepted")
    c.stage(3)
    if c.guard("least_privilege", not rbac.can("viewer", "users:manage"), "Role permits the action",
               "Server ignores token claims and loads the real role from the user store: 'viewer' lacks users:manage → 403", node="admin"):
        c.conclude("blocked", "Least privilege: permissions come from the server-side role, not from claims the client can edit.")
        return
    c.hit("admin")
    c.log("crit", "POST /admin/users/promote succeeded — attacker promoted to administrator")
    c.stage(4)
    if c.guard("mfa", True, "", "Sensitive admin actions require step-up MFA; the attacker cannot receive the OTP → denied", node="auth"):
        c.conclude("blocked", "Step-up MFA denied the privileged action even though the role check had been bypassed.")
        return
    c.hit("db")
    c.log("crit", "Attacker opens the admin console and exports customer data")
    c.conclude("breach", "Privilege escalation succeeded: a customer account now has full administrator control.")


# 11 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
def run_exfil(c: Ctx) -> None:
    from sqlalchemy import select
    from ..db import session_scope
    from ..models import Customer
    with session_scope() as db:
        sample = [dbsec.customer_view(x, True) for x in db.scalars(select(Customer).limit(3)).all()]
        raw = [[x.name, x.email_enc[:40] + "…", x.phone_enc[:30] + "…"] for x in db.scalars(select(Customer).limit(3)).all()]
    requested, cap = 50000, 100
    c.stage(0)
    c.log("warn", "Attacker holds a stolen analyst API key")
    c.stage(1)
    c.log("info", f"Request: GET /api/export/customers?limit={requested:,}")
    if c.guard("rbac", not rbac.can("analyst", "export:bulk"), "Role may export", "403 — role 'analyst' lacks permission export:bulk (admin only)", node="app"):
        c.conclude("blocked", "RBAC refused the bulk export: the analyst role cannot export customer data.")
        return
    if c.guard("least_privilege", requested > cap, "Within row cap", f"Row cap: {requested:,} requested, maximum {cap} per request → 400", node="db"):
        c.conclude("blocked", f"Least privilege capped exports at {cap} rows per request.")
        return
    c.stage(2)
    text = "\n".join(f"{x['name']},{x['email']},{x['phone']}" for x in sample)
    pii = rules.pii_scan(text)
    c.log("info", f"Export staged in cloud storage: {requested:,} customer rows")
    c.evidence(kv("DLP scan of outbound content (3-row sample)", [[k, f"{v} matches"] for k, v in pii.items()]))
    if c.guard("dlp", sum(pii.values()) > 0, "No sensitive patterns", f"DLP: {sum(pii.values())} PII patterns in a 3-row sample → extrapolated to {requested:,} rows; transfer blocked", node="cloud"):
        c.conclude("blocked", "DLP detected personal data in the outbound export and blocked it.")
        return
    c.stage(3)
    c.log("info", "Attacker pushes the archive to an external host (exfil.evil.example)")
    if c.guard("network_segmentation", True, "", "Egress allow-list: exfil.evil.example is not an approved destination → connection dropped", node="firewall"):
        c.conclude("blocked", "Egress filtering dropped the connection to the unapproved external host.")
        return
    c.hit("cloud")
    c.hit("db")
    if c.on("encryption_at_rest"):
        c.evidence(table("What the attacker now holds (storage layer, 3 of 50,000 rows)", ["Name", "email (stored)", "phone (stored)"], raw))
        c.log("success", "Stolen records are AES-256-GCM ciphertext — unreadable without the key held on the backend")
        c.metrics["records_readable"] = 0
        c.conclude("contained", f"{requested:,} rows left the network, but they are AES-256-GCM ciphertext: nothing is readable.", 0.2)
    else:
        c.evidence(table("What the attacker now holds (storage layer, 3 of 50,000 rows)", ["Name", "email", "phone"], [[x["name"], x["email"], x["phone"]] for x in sample]))
        c.log("crit", f"{requested:,} customer records stolen in readable form")
        c.metrics["records_readable"] = requested
        c.conclude("breach", f"{requested:,} customer records stolen in plaintext (names, emails, phone numbers).")


# 12 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
def run_mitm(c: Ctx) -> None:
    host = "shop.novamart.demo"
    ca_key, ca_cert = pki.root_ca()
    rk, rc = pki.rogue_ca()
    _, forged = pki.issue(rk, rc, host, 30, "Attacker Ltd")
    _, legit = pki.issue(ca_key, ca_cert, host, 90)
    v_forged, v_legit = pki.validate(forged, ca_cert, host), pki.validate(legit, ca_cert, host)
    login = "POST /login  username=arjun.m&password=Monsoon#Cart91  (fictional)"
    tls_view = crypto.seal(os.urandom(32), login.encode(), b"tls13-record").hex()
    c.stage(0)
    c.log("warn", "Attacker joins the victim's Wi-Fi (rogue access point) and positions between client and server")
    c.stage(1)
    c.log("info", f"Attacker intercepts the connection to {host} and presents a forged certificate")
    c.evidence(table("Forged certificate — chain validation", ["Check", "Result", "Detail"], [[x["check"], "PASS" if x["ok"] else "FAIL", x["detail"]] for x in v_forged["checks"]]))
    c.evidence(table("For comparison — the real server certificate", ["Check", "Result", "Detail"], [[x["check"], "PASS" if x["ok"] else "FAIL", x["detail"]] for x in v_legit["checks"]]))
    if c.guard("tls", not v_forged["valid"], "Certificate chain valid",
               "Certificate validation FAILED (issuer 'Totally Legit Certificate Authority' not in trust store). HSTS forbids click-through → connection aborted", node="waf"):
        c.log("success", "Browser aborted the connection: certificate not trusted")
        c.conclude("blocked", "TLS certificate validation rejected the attacker's forged certificate; no data was exposed.")
        return
    c.stage(2)
    c.hit("portal")
    c.log("crit", "No TLS validation: attacker decrypts and reads the victim's traffic")
    c.evidence(compare("What the attacker captures", {"title": "Without TLS (plaintext)", "tone": "danger", "code": login},
                       {"title": "With TLS 1.3 (what a sniffer would see)", "tone": "ok", "code": tls_view[:140] + "…"}))
    c.metrics["credentials_captured"] = 1
    c.conclude("breach", "Man-in-the-middle read the login request in cleartext, including the password.")


SCENARIOS_B = [
    _s("phishing", "Phishing Attack", "SOCIAL ENGINEERING", "phishing", "Phished credentials replayed",
       "A fake 'account suspended' email lures a user to a look-alike login page that captures their password.",
       "Internet (attacker)", "Authentication Server", {"C": 60, "I": 20, "A": 0},
       [("email", "Spoofed email delivered", "Look-alike sender, failed SPF/DKIM", ["internet", "firewall"]),
        ("click", "Victim clicks the link", "Fake login page loads", ["internet", "portal"]),
        ("capture", "Credential capture", "Password typed into the fake site", ["portal"]),
        ("replay", "Attacker replays password", "Stolen password used on the real login", ["internet", "waf", "auth"]),
        ("takeover", "Account takeover", "Attacker signed in as the victim", ["auth", "app"])],
       ["email_security", "mfa"], "Email scoring · MFA challenge failure", [("T1566.002", "Spearphishing Link"), ("T1078", "Valid Accounts")],
       {"contain": [("Reset the victim's password", "rotate_keys"), ("Revoke sessions", "revoke_sessions")],
        "eradicate": [("Block the phishing domain at the firewall", "block_ip"), ("Enable email security gateway", "enable_defence:email_security")],
        "recover": [("Enforce MFA for all staff", "enable_defence:mfa")]}, run_phishing),
    _s("ddos", "Distributed Denial of Service", "AVAILABILITY", "ddos", "Portal flooded by a botnet",
       "A botnet floods the storefront with junk requests until real customers can no longer shop.",
       "Internet (botnet)", "Customer Portal", {"C": 0, "I": 0, "A": 85},
       [("botnet", "Botnet assembled", "48,000 simulated devices ready", ["internet", "firewall"]),
        ("flood", "Volumetric flood", "Traffic reaches the edge; filters engage", ["firewall", "waf"]),
        ("load", "Origin load rises", "Remaining traffic hits portal and app", ["waf", "portal", "app"]),
        ("impact", "Service impact", "Availability measured", ["portal"])],
       ["cdn", "rate_limiting", "waf"], "Traffic anomaly · request-rate spike", [("T1498", "Network Denial of Service")],
       {"contain": [("Enable CDN scrubbing", "enable_defence:cdn"), ("Enable rate limiting", "enable_defence:rate_limiting")],
        "eradicate": [("Block botnet source ranges", "block_ip")],
        "recover": [("Verify portal availability", "none")]}, run_ddos),
    _s("ransomware", "Ransomware", "IMPACT · ENCRYPTION", "ransomware", "Ransomware encrypted the data servers",
       "Malware encrypts business files and demands payment. Runs only on an in-memory sandbox of fictional files.",
       "Admin workstation", "Database Server", {"C": 20, "I": 40, "A": 85},
       [("foothold", "Foothold on workstation", "Assumed breach of an admin PC", ["internet", "admin"]),
        ("lateral", "Lateral movement", "Attempt to reach app and database", ["admin", "app", "db"]),
        ("encrypt", "Mass file encryption", "Files encrypted with a throw-away key", ["app", "db", "cloud"]),
        ("recover", "Recovery", "Restore from the isolated backup vault", ["backup", "db"])],
       ["network_segmentation", "edr", "secure_backups"], "EDR entropy rule · zone policy · backup verification", [("T1486", "Data Encrypted for Impact"), ("T1021", "Remote Services")],
       {"contain": [("Isolate the application node", "isolate:app"), ("Revoke sessions", "revoke_sessions")],
        "eradicate": [("Enable EDR behavioural rules", "enable_defence:edr"), ("Enforce network segmentation", "enable_defence:network_segmentation")],
        "recover": [("Verify the latest backup", "verify_backup"), ("Restore from verified backup", "restore_backup"), ("Return node to production", "unisolate:app")]}, run_ransomware),
    _s("priv_esc", "Privilege Escalation", "BROKEN ACCESS · A01", "priv_esc", "Customer became administrator",
       "A normal customer edits their login token to claim the admin role and tries to use admin functions.",
       "Internet (customer account)", "Admin Dashboard", {"C": 60, "I": 55, "A": 0},
       [("login", "Ordinary customer login", "Attacker obtains a valid low-privilege token", ["internet", "waf", "auth"]),
        ("forge", "Forge token claims", "role: viewer → admin", ["auth", "portal"]),
        ("present", "Present forged token", "Admin API verifies the token", ["portal", "app", "admin"]),
        ("call", "Privileged API call", "Promote user / export data", ["admin", "app"]),
        ("stepup", "Step-up authentication", "Admin actions require OTP", ["admin", "auth"])],
       ["rbac", "least_privilege", "mfa"], "JWT signature failure · 403 on admin API", [("T1068", "Exploitation for Privilege Escalation"), ("T1078", "Valid Accounts")],
       {"contain": [("Revoke all sessions", "revoke_sessions"), ("Lock the attacker account", "lock_account")],
        "eradicate": [("Enforce signed-token verification (RBAC)", "enable_defence:rbac"), ("Apply least privilege", "enable_defence:least_privilege")],
        "recover": [("Audit role assignments", "none"), ("Run integrity scan", "integrity_scan")]}, run_priv_esc),
    _s("exfiltration", "Data Exfiltration", "COLLECTION · EXFILTRATION", "exfiltration", "Customer database exported",
       "A stolen API key is used to export the customer table in bulk and send it outside the company.",
       "Internet (stolen API key)", "Database Server", {"C": 90, "I": 0, "A": 0},
       [("auth", "Stolen API key", "Attacker authenticates as an analyst", ["internet", "waf", "app"]),
        ("request", "Bulk export request", "50,000 customer rows requested", ["app", "db"]),
        ("stage", "Stage in cloud storage", "Archive written for transfer", ["db", "cloud"]),
        ("exfil", "Transfer to external host", "Data leaves the network", ["cloud", "internet"])],
       ["rbac", "least_privilege", "dlp", "network_segmentation", "encryption_at_rest"], "Row-cap violation · DLP PII match · egress deny", [("T1530", "Data from Cloud Storage"), ("T1041", "Exfiltration Over C2 Channel")],
       {"contain": [("Revoke the stolen API key (sessions)", "revoke_sessions"), ("Isolate the cloud storage node", "isolate:cloud")],
        "eradicate": [("Enable DLP", "enable_defence:dlp"), ("Enable encryption at rest", "enable_defence:encryption_at_rest")],
        "recover": [("Notify regulator and customers (breach policy)", "none"), ("Return storage to production", "unisolate:cloud")]}, run_exfil),
    _s("mitm", "Man-in-the-Middle", "INTERCEPTION", "mitm", "Login traffic intercepted",
       "An attacker on public Wi-Fi sits between the customer and the shop and tries to read or alter traffic.",
       "Rogue Wi-Fi (attacker)", "Customer Portal", {"C": 75, "I": 35, "A": 0},
       [("position", "Attacker in position", "Rogue access point / ARP spoofing", ["internet", "firewall"]),
        ("intercept", "Intercept + forged certificate", "Attacker presents a certificate for the shop", ["firewall", "waf", "portal"]),
        ("read", "Read and modify traffic", "Credentials captured in cleartext", ["portal", "internet"])],
       ["tls"], "Certificate validation failure · HSTS", [("T1557", "Adversary-in-the-Middle")],
       {"contain": [("Revoke sessions of affected users", "revoke_sessions")],
        "eradicate": [("Enforce TLS 1.3 + certificate validation + HSTS", "enable_defence:tls")],
        "recover": [("Force password reset", "rotate_keys")]}, run_mitm),
]
