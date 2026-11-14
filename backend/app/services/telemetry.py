"""Simulated telemetry: seeded 7-day history and a background generator. All of it is tagged simulated=True."""
import asyncio
import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from ..config import settings
from ..db import session_scope
from ..models import SecurityEvent
from ..sim.defences import BY_ID
from . import events, state

# type -> (source, target, detection, action when blocked, defence that would stop it, severity)
TEMPLATES = {
    "sqli": ("internet", "waf", "WAF rule 942100 (SQLi)", "Request dropped (403)", "waf", "medium"),
    "xss": ("internet", "portal", "WAF rule 941100 (XSS)", "Request dropped (403)", "waf", "medium"),
    "brute_force": ("internet", "auth", "Failed-login counter", "Account locked 5 min", "rate_limiting", "medium"),
    "cred_stuffing": ("internet", "auth", "Breached-password lookup", "Login refused, reset forced", "breach_check", "high"),
    "ddos": ("internet", "firewall", "Traffic anomaly (req/s)", "CDN scrubbing engaged", "cdn", "high"),
    "port_scan": ("internet", "firewall", "IDS port-scan signature", "Source IP blocked", "ids", "low"),
    "phishing": ("internet", "portal", "Email gateway scoring", "Email quarantined", "email_security", "medium"),
    "csrf": ("internet", "app", "Origin header mismatch", "Request rejected (403)", "csrf_protection", "medium"),
    "mitm": ("internet", "waf", "Certificate validation failure", "Connection aborted", "tls", "high"),
    "exfiltration": ("app", "cloud", "DLP PII pattern match", "Transfer blocked", "dlp", "high"),
    "priv_esc": ("internet", "admin", "JWT signature failure", "Token rejected (401)", "rbac", "high"),
    "ransomware": ("admin", "db", "EDR entropy rule", "Process killed, host isolated", "edr", "critical"),
}
WEIGHTS = {"port_scan": 22, "sqli": 16, "brute_force": 13, "xss": 9, "cred_stuffing": 9, "ddos": 6, "phishing": 8, "csrf": 4, "mitm": 3,
           "exfiltration": 3, "priv_esc": 3, "ransomware": 2}


def seed_history() -> None:
    with session_scope() as db:
        if (db.scalar(select(func.count(SecurityEvent.id))) or 0) > 0:
            return
    rng = random.Random(2026)
    now = datetime.now(timezone.utc)
    types = list(WEIGHTS)
    for _ in range(260):
        t = rng.choices(types, weights=[WEIGHTS[x] for x in types])[0]
        src, dst, det, act, _, sev = TEMPLATES[t]
        r = rng.random()
        result = "blocked" if r < 0.84 else "contained" if r < 0.93 else "breach" if r < 0.97 else "detected"
        if result == "breach":
            sev, act = "critical", "None — breach in progress"
        elif result == "contained":
            act = "Contained / recovered"
        when = now - timedelta(minutes=rng.randint(5, 7 * 24 * 60))
        events.emit(t, src, dst, sev, det, act, result, "seed", True, None, {"kind": "seed"}, ts=when, publish=False)


def _event_now() -> dict:
    t = random.choices(list(WEIGHTS), weights=[WEIGHTS[x] for x in WEIGHTS])[0]
    src, dst, det, act, defence, sev = TEMPLATES[t]
    if t == "ransomware":  # keep the live feed believable: background noise is low-severity
        t, (src, dst, det, act, defence, sev) = "port_scan", TEMPLATES["port_scan"]
    guarded = state.live.defences.get(defence, False)
    if guarded:
        return events.emit(t, src, dst, "low" if sev in ("low", "medium") else "medium", det, act, "blocked", "background", True, None, {"kind": "background"})
    return events.emit(t, src, dst, "medium", "None — no control active", "Allowed through (defence OFF)", "detected", "background", True, None,
                       {"kind": "background", "note": f"{BY_ID[defence]['name']} is OFF"})


async def background_loop() -> None:
    while True:
        await asyncio.sleep(random.uniform(4.5, 8.5))
        if settings.telemetry_enabled and not state.live.running:
            try:
                await asyncio.get_running_loop().run_in_executor(None, _event_now)
            except Exception:  # never let telemetry kill the server
                pass
