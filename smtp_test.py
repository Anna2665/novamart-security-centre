r"""NovaMart - step-by-step Gmail SMTP check.

Run it from the folder that contains run.py:
    .\venv\Scripts\python.exe smtp_test.py
It reads the same .env the server reads and shows exactly which step fails.
"""
import smtplib
import ssl
import sys
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))
from app.config import settings  # noqa: E402  (same settings the server uses)

host, port, mode = settings.smtp_host, settings.smtp_port, settings.smtp_security
password = settings.smtp_password.replace(" ", "")   # Gmail shows App Passwords with spaces; they are not part of it
ctx = ssl.create_default_context()

print("Settings the app really loads from .env:")
print(f"  host       : {host}")
print(f"  port       : {port}")
print(f"  security   : {mode}   (use port 465 with ssl, or port 587 with starttls)")
print(f"  user       : {settings.smtp_user}")
print(f"  password   : {len(password)} characters (a Gmail App Password has 16)")
print(f"  dev echo   : {settings.otp_dev_echo}")
print()

conn = None


def step(name, action):
    """Run one step; print OK or the exact error; return False on failure."""
    try:
        action()
        print(f"[ OK ]   {name}")
        return True
    except Exception as exc:
        print(f"[FAIL]   {name}\n         -> {type(exc).__name__}: {exc}")
        return False


def connect():
    global conn
    conn = smtplib.SMTP_SSL(host, port, timeout=20, context=ctx) if mode == "ssl" else smtplib.SMTP(host, port, timeout=20)


def send():
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = settings.smtp_user, settings.smtp_user, "NovaMart SMTP test"
    msg.set_content("If you can read this on your phone, NovaMart email works.")
    conn.send_message(msg)


ok = step(f"connect to {host}:{port} ({'TLS from the start' if mode == 'ssl' else 'plain'})", connect)
if ok and mode == "starttls":
    ok = step("EHLO", conn.ehlo) and step("STARTTLS (switch to encrypted)", lambda: conn.starttls(context=ctx))
if ok:
    ok = step("EHLO", conn.ehlo)
if ok:
    ok = step("login with the App Password", lambda: conn.login(settings.smtp_user, password))
if ok:
    ok = step("send a test email to yourself", send)
print()
print("RESULT:", "EMAIL SENT - open Gmail on your phone." if ok else "FAILED at the step marked [FAIL] above.")
