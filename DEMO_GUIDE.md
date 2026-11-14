# Demo guide — NovaMart shop + Security Centre

Two browser windows side by side: the **shop** (`http://127.0.0.1:8000/#/`) and the **Security Centre** (`#/soc`, sign in as `admin`).
The same script is built into the app: **Security Centre → Guided Demo** (plain language, with *Do / See / Say* for every step).

## Attacks you can fire at the live shop (Attacker's toolbox, bottom-left of the shop)

| Attack | Where | Defences OFF | Defences ON |
|---|---|---|---|
| SQL injection | Product search box | Red panel: the query that ran and the hidden rows that leaked (from an isolated mock) | Green panel: blocked by the web application firewall; input validation and parameterised queries are further layers |
| Stored XSS | Review box on a product page | Red panel: the script was saved as typed | Green panel: blocked by the firewall, or sanitised |
| IDOR (reading another customer's order) | `#/orders/NM-1001` | Red panel: another customer's order is shown | Green panel: access denied by the ownership (RBAC) check |
| Price tampering | Security Centre → Database Security → tamper, then buy in the shop | Order accepted at the fake price | Checkout refused: the signed price record no longer verifies |
| Checkout flood | Toolbox → "Fire 10 orders at once" | All 10 go through | The rate limiter stops requests beyond 8 per minute |
| Fraud / risky order | Order 5 × PixelPad tablet | — (the fraud score is always on) | Held for review; staff approve or reject in **Store Orders & Fraud** |

Each attack on the shop is also replayed in the Security Centre (pipeline, CIA score, incident), so the audience sees both sides.

## The 12 attacks and what stops each one

CIA = which pillar of the triad the attack mainly damages (C Confidentiality, I Integrity, A Availability).
"Defences" are the switches on the **Attack Lab** page. Turn them off to see the attack succeed, on to see it stop.

| # | Attack | Hits | What the simulation does | Defences that stop it | How it is detected |
|---|---|---|---|---|---|
| 1 | **SQL Injection** | C | Crafted login payload → edge → login endpoint → DB query (runs on a throw-away in-memory mock) | WAF · input validation · parameterised queries · IDS | WAF/IDS signature, parameterised query |
| 2 | **Database value tampering** (₹1,499 → ₹1) | I | Stolen service token → price-update API → unauthorised UPDATE → integrity check | RBAC · least privilege · DB integrity monitoring · digital signatures | SHA-256 mismatch, RSA-PSS signature failure |
| 3 | **Cross-Site Scripting (stored)** | C | Malicious review posted → stored → victim loads page → cookie exfiltrated | WAF · input validation · Content Security Policy | WAF XSS rule, CSP violation report |
| 4 | **CSRF** | I | Victim visits attacker page → forged cross-site POST moves ₹25,000 store credit | CSRF tokens + SameSite cookies · IDS | Origin/Referer anomaly, missing token |
| 5 | **Brute force** | C | Bot guesses passwords until one works → account takeover | Rate limiting + lockout · WAF · MFA | Failed-login counter, lockout |
| 6 | **Credential stuffing** | C | Breached list replayed across accounts → valid pair → takeover | Rate limiting · breached-password check · MFA | Login-failure velocity, breached-password lookup |
| 7 | **Phishing** | C | Spoofed email → click → credentials captured → attacker replays them | Email security & awareness · MFA | Email scoring, MFA challenge failure |
| 8 | **DDoS** | A | Botnet assembles → volumetric flood → origin load → service impact | CDN / scrubbing · rate limiting · WAF | Traffic anomaly, request-rate spike |
| 9 | **Ransomware** | A (+I) | Foothold → lateral movement → mass encryption of an in-memory sandbox of fictional files → recovery | Network segmentation · EDR · secure backups | EDR entropy rule, zone policy, backup verification |
| 10 | **Privilege escalation** | C, I | Customer forges token claims → calls admin API → step-up auth | RBAC · least privilege · MFA | JWT signature failure, 403 on admin API |
| 11 | **Data exfiltration** | C | Stolen API key → bulk export → staged → sent externally | RBAC · least privilege · DLP · segmentation · encryption at rest | Row-cap violation, DLP PII match, egress deny |
| 12 | **Man-in-the-Middle** | C, I | Attacker in position → intercepts → reads/modifies login traffic | TLS 1.3 + certificate validation | Certificate validation failure, HSTS |

Result of every run: **blocked** (a defence stopped it), **contained** (it got partway, damage limited) or **breach**.
**Compare OFF vs ON** on any attack runs the same scenario twice (defences off, then on) as a dry run with no side effects.

## Suggested 10-minute demo

1. **Idea (1 min)** — Guided Demo page: shop = System A, Security Centre = System B, CIA triad.
2. **Customer journey (2 min)** — In the shop: Create account → the professional email with a 6-digit code arrives → confirm → search → add to cart → checkout → order confirmation and receipt email.
3. **SQL injection, defences OFF then ON (2 min)** — Toolbox → `' OR 1=1 --`. Red panel with leaked rows; switch **Defences → All on**; repeat; green panel. Show the alert in the Security Centre.
4. **Access control (1 min)** — Toolbox → "Open order NM-1001", OFF then ON.
5. **Price tampering and signatures (2 min)** — Database Security → modify a price, run the integrity scan, try to buy it in the shop (refused), then **Restore trusted version**.
6. **Fraud review (1 min)** — Order 5 tablets → held → **Store Orders & Fraud** → Approve → receipt email arrives.
7. **Recovery (1 min)** — Attack Lab → Ransomware (defences off) → Incident Response → Backup & Recovery.

Keep the Encryption Lab, Digital Signatures page, Network Map and Threat Intelligence in reserve for questions.

## Likely viva questions

- **Why is this "simulated"?** Running real attacks needs real targets and is illegal against systems you don't own. The simulation evaluates *real defence rules* against scripted attack steps in an isolated mock, which is how security training ranges work. The crypto and OTP parts are real.
- **Which pillar does each defence protect?** C: encryption, MFA, TLS, DLP, WAF. I: signatures, hashing, integrity monitoring, CSRF tokens, RBAC. A: backups, rate limiting, CDN, segmentation.
- **Why AES-GCM and not plain AES?** GCM is authenticated: tampering is detected, not just hidden. (Lab → tamper mode.)
- **Why Argon2id for passwords?** Memory-hard, so GPU cracking is expensive; salted per user.
- **Why sign *and* hash the record?** A hash alone can be recomputed by an attacker who edits both. A signature needs the private key, which never leaves the server.
- **How is the OTP safe?** Generated with a CSPRNG, only an HMAC of it is stored, single-use, 60 s expiry, attempt limit, resend invalidates the old code.
- **What would you add in production?** WAF in front, secrets in a vault, SIEM export, hardware-backed keys, per-tenant rate limits.

## Before you present — checklist

- [ ] `.env` has SMTP set, `OTP_DEV_ECHO=false`, and **Settings → Send test email** arrives in the demo mailbox
- [ ] You know the `admin` and `shopper` passwords (`data/demo_credentials.txt`) and can open the demo mailbox on your phone/laptop
- [ ] `frontend/dist` is built and `python run.py` starts without warnings
- [ ] In **Settings** click **Reset to a clean state** just before presenting so the dashboard starts clean
- [ ] Have a backup plan if the venue Wi-Fi blocks SMTP: use a phone hotspot (SMTP port 587)
