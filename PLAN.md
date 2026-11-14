# NovaMart + Security Centre — Architecture & Implementation Plan

**Cybersecurity of an E-Commerce Platform.** Two cooperating systems in one codebase:

* **System A — NovaMart**, a working online shop (catalogue, search, reviews, cart, checkout, orders, accounts).
* **System B — Security Centre**, the staff control room that attacks, defends, monitors and recovers System A.

Customers and staff are different account types. Customers use the shop only; every Security Centre endpoint
refuses a customer token. The shop's own security decisions (firewall, input validation, signature checks,
ownership checks, rate limits, fraud score) read the same 21 defence switches as the Security Centre, so flipping a
switch changes the behaviour of the live shop immediately.

## 1. What is real and what is simulated

| Real (actually executes) | Simulated (clearly labelled) |
|---|---|
| Shop accounts, search, reviews, cart, checkout, orders; fraud score and review queue | The attacker (you, with the toolbox and the Attack Lab) |
| 6-digit email OTP, order receipts and security alerts over real SMTP (HTML emails) | Seeded 7-day security history and background telemetry |
| AES-256-GCM of customer details, RSA-PSS signed product and order records, Argon2id, TOTP | Ransomware, DDoS volume, network map animations |
| RBAC, account lockout, rate limits, firewall rules, hash-chained audit log, signed backups | |
| SQL injection against an **isolated in-memory mock** of fake data (read-only) | |

No real systems or customer data are touched. No destructive payloads exist in the code.

## 2. Architecture

```
React + TS + Tailwind + Framer Motion + React Flow + Recharts          (frontend/)
        │  REST (/api/*)            │  WebSocket (/api/ws)
        ▼                           ▼
FastAPI  ── routers ── services ── sim engine (scenarios + defence rules)   (backend/app/)
        │                  │
        │                  ├─ security/  crypto · signing · pki · passwords · otp · tokens · rbac
        │                  └─ services/  email · audit chain · events · state · dbsec · backup · incidents
        ▼
SQLAlchemy 2 → SQLite (zero-setup default) or PostgreSQL (DATABASE_URL), Alembic migrations
```

* **Event-driven:** a scenario run is computed by the engine, then replayed stage-by-stage over the WebSocket
  (node colours, logs, events). The UI, topology, CIA gauges and feed all update from the same stream.
* **Defence engine:** every scenario stage asks `ctx.guard(defence_id, rule(...))`. A defence that is OFF is not
  evaluated; one that is ON runs a real rule (regex WAF signatures, parameterised query, CSP parse, token
  checks, entropy-based EDR, token-bucket limiter, certificate validation, ...) and may block the stage.
* **Same attack, different outcome:** `Defences ENABLED` vs `DISABLED` (or any custom mix of the 21 toggles) and a
  side-by-side *Compare* run.
* **Secrets:** SMTP password, JWT secret, OTP pepper and the master AES key come from environment variables
  (or are generated on first start into `data/`), never from frontend code. Private keys never leave the backend.

## 3. The 12 attacks and their defences

| # | Attack | Pipeline | Rule that decides the outcome | Defences that stop it |
|---|---|---|---|---|
| 1 | **SQL Injection** | Attacker → WAF → Login API → App → DB | Real injected query against mock SQLite DB: unsafe string-built query returns every user; bound query returns none | WAF signatures, input validation (allow-list), **parameterised queries**, IDS alert |
| 2 | **Database value tampering** | Attacker → API → DB | Price ₹1,499 → ₹1 written to the real products table; SHA-256 recomputed, RSA-PSS signature verified | Least-privilege DB role (write denied), **DB integrity monitoring (hash)**, **digital signatures**, auto-restore of trusted signed version |
| 3 | **XSS** (stored) | Attacker → WAF → Portal → Victim browser | Script payload in a product review; sanitiser, output encoder and CSP header parsed | WAF, input sanitisation + output encoding, **CSP** (no inline script) |
| 4 | **CSRF** | Evil site → victim browser → App | Cross-site POST evaluated: Origin, cookie SameSite, CSRF token | **CSRF token**, **SameSite cookies**, Origin check |
| 5 | **Brute force** | Bot → WAF → Auth server | 25 real Argon2 guesses against a mock account | **Rate limiting + account lockout**, **MFA** (password alone is not enough), WAF bot rule |
| 6 | **Credential stuffing** | Botnet → WAF → Auth → App | 30 breached email/password pairs vs mock accounts | Breached-password check, rate limiting, **MFA** |
| 7 | **Phishing** | Attacker → mailbox → fake login → Auth | Email scored: look-alike domain, SPF/DKIM/DMARC, urgency, link mismatch | Email security + awareness, **MFA** (stolen password useless) |
| 8 | **DDoS** | Botnet → CDN/WAF → Portal → App | 60-second traffic model, server capacity vs filtered traffic | **CDN scrubbing**, **rate limiting**, WAF bot rules, auto-scaling headroom |
| 9 | **Ransomware** | Admin PC → App → DB → Storage | Real entropy of files before/after AES-GCM sandbox encryption | **EDR** (entropy + rate rule), **network segmentation**, **secure backups** (restore verified copy) |
| 10 | **Privilege escalation** | Customer → Portal → App → Admin | Real JWT with forged `role=admin` claim; permission matrix | **RBAC** + signed-token verification, **least privilege**, **MFA step-up** |
| 11 | **Data exfiltration** | Insider/API → DB → Cloud → Internet | 50,000-row export request, PII regex scan, egress allow-list | **DLP**, least privilege (row cap), egress segmentation, **encryption at rest** (stolen data = ciphertext) |
| 12 | **Man-in-the-Middle** | Attacker ⇄ client ⇄ Portal | Forged certificate validated against the real CyberGuard CA; plaintext vs TLS ciphertext capture | **TLS 1.3**, **certificate validation**, HSTS |

Result of a run is one of `blocked` · `contained` (attack got in but was detected/recovered) · `breach`.
Each run reports CIA impact, detection mechanism, defence used, timeline and evidence panels (query, diff, tables, charts).

## 4. Defence controls (21 toggles)

Preventive: WAF · SQL-injection protection (parameterised queries) · input validation & sanitisation · CSP/output encoding ·
CSRF protection · network segmentation · rate limiting & lockout · MFA · RBAC · least privilege · TLS 1.3 ·
encryption at rest · digital signatures · breached-password check · CDN scrubbing · email security · DLP.
Detective: IDS · EDR · DB integrity monitoring. Corrective: secure backups.

## 5. Screens

**Shop (public):** home & catalogue with search, categories and sorting · product page with reviews · cart · checkout (UPI / card / cash on delivery, demo) · sign in & register with email code · my orders · my account (profile, authenticator app) · *Attacker's toolbox* (demo helper).

**Security Centre (staff):** Guided Demo · Security Overview · Store Orders & Fraud · CIA Scores · Threat Intelligence · Network Map · Attack Lab · Incident Response · Backup & Recovery · Encryption Lab · Digital Signatures · Accounts & Access · Database Security · Audit Log · Settings.

## 6. Authentication flow

email/username + password → Argon2id verify → server generates 6-digit OTP with `secrets` → HMAC-hashed and stored with 60 s expiry,
3 attempts → emailed to the registered address over SMTP → OTP screen with countdown, resend, wrong-OTP alert →
JWT session issued only after verification (customers can register; a new account is confirmed with the same emailed code). Optional authenticator-app TOTP (RFC 6238) enrolled from the account page (customers) or Accounts & Access (staff).
If SMTP is not configured the UI says so plainly — delivery is never faked. (`OTP_DEV_ECHO=true` is an explicit,
clearly-bannered developer mode that shows the code on screen instead.)

## 7. Build phases (all completed in this repo)

1. Structure, models, config · 2. Crypto, signatures, PKI · 3. Auth, email OTP, TOTP, RBAC · 4. Defence + simulation engine, 12 scenarios ·
5. DB security, backup vault, incidents, CIA, events + WebSocket · 6. Customer accounts, shop API, fraud score, live attacks on the shop · 7. NovaMart storefront and the light Security Centre (15 pages) · 8. Tests (pytest + Playwright) · 9. Docs.
