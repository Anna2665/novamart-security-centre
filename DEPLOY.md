# Deploying NovaMart (Netlify pages + Railway API)

```
 browser ──► Netlify  https://novamart-security-centre.netlify.app        (shop + Security Centre pages)
    │
    └──────► Railway  https://novamart-api-production-e7400519.up.railway.app   (FastAPI: login, shop, attacks, live feed)
```

Netlify cannot run the Python server, so the two halves are hosted separately and the pages are told where the API lives.
Both deploy automatically on every push to `main`.

## 1. API on Railway (project `novamart`, service `novamart-api`)
Railway builds the `Dockerfile`. Variables (Railway → novamart-api → Variables):

| Variable | Value |
|---|---|
| `CORS_ORIGINS` | `https://novamart-security-centre.netlify.app` |
| `DEMO_EMAIL` | the mailbox that receives staff sign-in codes |
| `RESEND_API_KEY` | key from resend.com (create the account with the same address as `DEMO_EMAIL`) |
| `OTP_DEV_ECHO` | `true` shows codes on screen; set `false` once e-mail works |
| `CG_ADMIN_PASSWORD`, `CG_ANALYST_PASSWORD`, `CG_VIEWER_PASSWORD`, `CG_SHOPPER_PASSWORD` | the demo passwords |

Railway's lower plans block outgoing SMTP, so e-mail goes over HTTPS (Resend) instead of Gmail SMTP.
The SQLite database lives inside the container, so demo data resets on every redeploy.

`render.yaml` is an alternative for Render (Render needs a card on file even for its free plan).

## 2. Pages on Netlify (project `novamart-security-centre`)
`netlify.toml` builds `frontend/`. One variable (Netlify → Project configuration → Environment variables):

| Variable | Value |
|---|---|
| `VITE_API_URL` | `https://novamart-api-production-e7400519.up.railway.app` |

If the API address ever changes, update this variable and the `connect-src` list in `netlify.toml`.

## 3. Pages you can open
| Page | Address |
|---|---|
| Shop | `/#/` |
| Customer sign-in / sign-up | `/#/signin`, `/#/register` |
| Cart, checkout, orders, account | `/#/cart`, `/#/checkout`, `/#/orders`, `/#/account` |
| Security Centre sign-in | `/#/soc` |
| Attack Lab | `/#/soc/attacks` |
| Guided Demo | `/#/soc/guide` |

Running locally is unchanged: `python run.py` serves everything on one port.
