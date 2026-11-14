"""The 21 interactive defence controls. A defence has no animation of its own: scenarios evaluate real rules when it is ON."""

D = lambda id_, name, kind, pillars, nodes, desc, weight=1: dict(  # noqa: E731
    id=id_, name=name, kind=kind, pillars=pillars, nodes=nodes, description=desc, weight=weight)

DEFENCES: list[dict] = [
    D("waf", "Web Application Firewall", "preventive", ["C", "I", "A"], ["waf"], "Regex/signature rules for SQLi, XSS and bot traffic at the edge."),
    D("sqli_protection", "SQL-injection protection (parameterised queries)", "preventive", ["C", "I"], ["app", "db"], "Queries are built with bound parameters, so input is data, never SQL.", 2),
    D("input_validation", "Input validation & sanitisation", "preventive", ["C", "I"], ["portal", "app"], "Allow-list validation, sanitisation on write and output encoding on read."),
    D("csp", "Content Security Policy", "preventive", ["C", "I"], ["portal"], "Browser blocks inline scripts and unknown origins."),
    D("csrf_protection", "CSRF tokens + SameSite cookies", "preventive", ["I", "C"], ["portal", "app"], "Per-session anti-forgery token, SameSite=Strict cookie and Origin check.", 2),
    D("network_segmentation", "Network segmentation", "preventive", ["C", "I", "A"], ["firewall", "db", "cloud"], "Zones with deny-by-default rules and an egress allow-list."),
    D("rate_limiting", "Rate limiting & account lockout", "preventive", ["A", "C"], ["waf", "auth"], "Token-bucket limiter per IP and lockout after repeated failures.", 2),
    D("mfa", "Multi-factor authentication", "preventive", ["C", "I"], ["auth"], "Email OTP / TOTP required after the password.", 3),
    D("rbac", "Role-based access control", "preventive", ["C", "I"], ["app", "admin"], "Permissions checked server-side on every request; signed tokens only.", 2),
    D("least_privilege", "Least privilege", "preventive", ["C", "I"], ["app", "db", "admin"], "Service accounts and roles hold only the permissions they need; row caps on exports.", 2),
    D("tls", "TLS 1.3 + certificate validation", "preventive", ["C", "I"], ["internet", "waf"], "Encrypted channel; certificate chain, hostname and expiry validated; HSTS.", 2),
    D("encryption_at_rest", "Encryption at rest (AES-256-GCM)", "preventive", ["C"], ["db", "enc", "cloud"], "Stored PII and exports are ciphertext; a stolen copy is unreadable.", 3),
    D("digital_signatures", "Digital signatures (RSA-PSS)", "preventive", ["I"], ["db", "app"], "Every critical record is signed; modifications fail verification.", 3),
    D("db_integrity", "Database integrity monitoring", "detective", ["I"], ["db", "soc"], "Continuous SHA-256 comparison of records against trusted hashes; auto-restore.", 3),
    D("secure_backups", "Secure backups", "corrective", ["A", "I"], ["backup"], "Isolated, encrypted, signed snapshots verified before restore.", 3),
    D("breach_check", "Breached-password detection", "preventive", ["C"], ["auth"], "Reject credentials found in breach corpora (k-anonymity style lookup)."),
    D("cdn", "CDN / DDoS scrubbing", "preventive", ["A"], ["firewall", "waf"], "Edge network absorbs and scrubs volumetric floods before the origin.", 3),
    D("email_security", "Email security & awareness", "preventive", ["C"], ["portal"], "SPF/DKIM/DMARC checks, look-alike domain detection, user warning banners."),
    D("dlp", "Data loss prevention", "preventive", ["C"], ["cloud", "db"], "Scans outbound data for PII patterns and blocks bulk transfers.", 2),
    D("ids", "Intrusion detection (IDS)", "detective", ["C", "I", "A"], ["soc", "firewall"], "Signature/behaviour alerts raised to the Security Monitoring Centre."),
    D("edr", "Endpoint detection & response (EDR)", "detective", ["I", "A", "C"], ["admin", "app"], "Entropy and write-rate rules kill ransomware and isolate the host.", 2),
]
BY_ID = {d["id"]: d for d in DEFENCES}
IDS = [d["id"] for d in DEFENCES]




def pillar_baseline(enabled: dict[str, bool]) -> dict[str, float]:
    out = {}
    for p in "CIA":
        total = sum(d["weight"] for d in DEFENCES if p in d["pillars"])
        on = sum(d["weight"] for d in DEFENCES if p in d["pillars"] and enabled.get(d["id"]))
        out[p] = round(35 + 63 * on / total, 1)
    return out
