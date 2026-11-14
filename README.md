# NovaMart + Security Centre — Cybersecurity of an E-Commerce Platform

Two systems that work together (like a real company would run them):

| System | What it is | Where |
|---|---|---|
| **A. NovaMart shop** | A working online store. Customers register (email code), search, read and write reviews, add to cart, check out, and see their orders. | `http://127.0.0.1:8000/#/` |
| **B. Security Centre** | The control room that protects the shop: live attack lab, 21 switchable defences, CIA scores, fraud review, incident response, backups, cryptography labs. Staff only. | `http://127.0.0.1:8000/#/soc` |

You attack the shop on purpose. With the defences **off** the attack works; with them **on** it is stopped. Everything is judged by the **CIA triad** (Confidentiality, Integrity, Availability).
Open **Security Centre → Guided Demo** for a step-by-step presentation script written in plain language.

## What is real and what is simulated

| Real (actually executed) | Simulated (safe) |
|---|---|
| The shop: accounts, search, reviews, cart, checkout, orders, order history | The attacker (you play them with the in-shop *Attacker's toolbox* and the Attack Lab) |
| Email codes and order receipts over real SMTP, professional HTML emails | SQL injection runs against an isolated in-memory copy of fake data, never the real database |
| Argon2id password hashing, AES-256-GCM encryption of customer details, RSA-PSS signed product and order records | Ransomware, DDoS volume and the network map are animations of what would happen |
| Role-based access (customers can never open the Security Centre), lockout, rate limiting, firewall rules, hash-chained audit log | Historical attack statistics (labelled SIM) |
| Fraud risk score; high-risk orders are held until staff approve or reject them | |

## Run it (Windows PowerShell or any terminal)

Requires Python 3.11+ and Node 20+ (Node is only needed to rebuild the screens; the zip already includes the built screens).

```powershell
cd cyberguard-x            # the folder that contains run.py (it may be nested: cyberguard-x\cyberguard-x)
python -m venv venv
venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt
copy .env.example .env     # then edit .env (see "Real email" below)
python run.py              # open http://127.0.0.1:8000
```

* Use `python -m pip` (not `pip`) — some Windows machines block `pip.exe`.
* **Upgrading from the earlier CyberGuard X version?** Delete the old `data` folder first (it has the old database layout), then start again.
* The first start creates demo accounts and writes their passwords **once** to `data\demo_credentials.txt`:
  `admin` / `analyst` / `viewer` for the Security Centre and `shopper` (a sample customer). Or set `CG_*_PASSWORD` in `.env`.
* Rebuild the screens only if you change the code: `cd frontend && npm install && npm run build`.

## Real email (needed for the demo)

Staff sign-in codes go to `DEMO_EMAIL`; customers get their code at the address they register with; order receipts go to the customer.

1. Google Account → Security → turn **2-Step Verification** on → **App passwords** → create one named "NovaMart".
2. In `.env` set `SMTP_USER` (the Gmail address), `SMTP_PASSWORD` (the 16-character app password, **not** your normal password), `SMTP_FROM=NovaMart <that address>`, and `DEMO_EMAIL`.
3. Restart `python run.py`. Open **Security Centre → Settings → Send test email** to check it before the demo.

If SMTP is missing or wrong the screen says so honestly. With `OTP_DEV_ECHO=true` the code is shown on screen in a yellow "practice mode" box instead — handy for rehearsing, never for the real demo.

## Tests

```bash
cd backend && python -m pytest -q          # 79 tests: crypto, API, RBAC, OTP, all 12 attacks, shop, SMTP delivery, migrations
pip install -r e2e/requirements.txt && python -m playwright install chromium
python -m pytest e2e -q                    # 21 real-browser tests of the shop and the Security Centre
```

Set `CHROME_PATH=/path/to/chrome` to use your own Chrome. `TEST_DATABASE_URL=postgresql+psycopg://…` runs the backend suite on PostgreSQL (it wipes that schema).

## Layout

```
backend/app/services/shop.py     the shop: search, reviews, checkout, fraud score, orders
backend/app/sim/                 12 attack scenarios, 21 defences, staged engine
backend/app/security/            AES-GCM, signing, OTP, Argon2id, TOTP, JWT, RBAC
backend/app/services/email.py    professional HTML emails (code, receipt, security alert)
frontend/src/shop/               the NovaMart storefront
frontend/src/pages/              the Security Centre pages
DEMO_GUIDE.md                    attack/defence table and a short demo script
PLAN.md                          architecture and build plan
```

## Security notes

* Customers and staff are separate: a customer token is refused by every Security Centre endpoint (verified route-by-route in the test suite).
* The shop never trusts the browser: prices are re-read from signed database records at checkout.
* Secrets come from the environment or `data/secrets.json` (mode 0600). The API never returns password hashes, private keys or codes.
* Strict CSP and security headers on every response. All attacks use harmless payloads against an isolated mock; do not point this tool at systems you do not own.
