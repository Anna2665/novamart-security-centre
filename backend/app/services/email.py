"""Real SMTP delivery of transactional e-mail (sign-in codes, order receipts, security alerts).

Every message is multipart: a plain-text part for old clients and a responsive HTML part.
Never pretends: `send_mail` returns an honest DeliveryResult (sent | failed | not_configured).
"""
import json
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, parseaddr
from html import escape

from ..config import settings


@dataclass
class DeliveryResult:
    status: str  # sent | failed | not_configured
    detail: str


# --------------------------------------------------------------------------------------- helpers
INDIGO, INDIGO_DARK, INK, MUTED, LINE, PAGE = "#4F46E5", "#3730A3", "#111827", "#6B7280", "#E5E7EB", "#F3F4F6"


def _brand() -> str:
    return settings.brand_name or "NovaMart"


def _sender_address() -> str:
    return parseaddr(settings.smtp_from or "")[1] or settings.smtp_user or "no-reply@localhost"


def _ttl_text(seconds: int) -> str:
    if seconds % 60 == 0 and seconds >= 60:
        m = seconds // 60
        return f"{m} minute{'s' if m != 1 else ''}"
    return f"{seconds} seconds"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")


def _message(to: str, subject: str, text: str, html: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((f"{_brand()} Security", _sender_address()))
    msg["To"] = to
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=(_sender_address().split("@")[-1] or "localhost"))
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Auto-Response-Suppress"] = "All"
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    return msg


def _rows(rows: list[tuple[str, str]]) -> str:
    return "".join(
        f'<tr><td style="padding:8px 0;font-size:13px;color:{MUTED};width:38%;border-bottom:1px solid {LINE}">{escape(k)}</td>'
        f'<td style="padding:8px 0;font-size:13px;color:{INK};font-weight:600;border-bottom:1px solid {LINE}">{escape(v)}</td></tr>'
        for k, v in rows)


def _layout(title: str, preheader: str, body: str) -> str:
    brand = _brand()
    year = datetime.now(timezone.utc).year
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light"><title>{escape(title)}</title></head>
<body style="margin:0;padding:0;background:{PAGE};font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:{PAGE}">{escape(preheader)}&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;&#847;&zwnj;&nbsp;</div>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:{PAGE};padding:32px 12px"><tr><td align="center">
 <table role="presentation" width="560" cellspacing="0" cellpadding="0" style="width:100%;max-width:560px">
  <tr><td style="padding:0 4px 16px">
   <table role="presentation" cellspacing="0" cellpadding="0"><tr>
    <td style="background:{INDIGO};border-radius:9px;width:34px;height:34px;text-align:center;color:#fff;font-weight:800;font-size:18px;line-height:34px">{escape(brand[:1].upper())}</td>
    <td style="padding-left:10px;font-size:19px;font-weight:700;color:{INK};letter-spacing:-0.2px">{escape(brand)}</td>
   </tr></table>
  </td></tr>
  <tr><td style="background:#ffffff;border:1px solid {LINE};border-radius:14px;padding:32px 32px 28px">{body}</td></tr>
  <tr><td style="padding:20px 8px 0;text-align:center;font-size:12px;line-height:1.6;color:{MUTED}">
   This is an automated message from {escape(brand)} Security &mdash; please do not reply.<br>
   &copy; {year} {escape(brand)}. {escape(brand)} is a demonstration store built for an academic security project.
  </td></tr>
 </table>
</td></tr></table></body></html>"""


def _notice(text: str, tone: str = "warn") -> str:
    bg, bd, fg = {"warn": ("#FFFBEB", "#FDE68A", "#92400E"), "info": ("#F3F4F6", LINE, "#374151")}[tone]
    return (f'<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:22px"><tr>'
            f'<td style="background:{bg};border:1px solid {bd};border-radius:10px;padding:12px 14px;font-size:13px;line-height:1.55;color:{fg}">{text}</td></tr></table>')


# --------------------------------------------------------------------------------------- transport
def _send_https(to: str, subject: str, text: str, html: str) -> DeliveryResult:
    """Send through the Resend HTTPS API (port 443), for hosts that block outgoing SMTP."""
    payload = json.dumps({"from": settings.resend_from, "to": [to], "subject": subject, "text": text, "html": html}).encode()
    req = urllib.request.Request("https://api.resend.com/emails", data=payload, method="POST",
                                 headers={"Authorization": f"Bearer {settings.resend_api_key}", "Content-Type": "application/json", "User-Agent": "NovaMart/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = json.loads(r.read() or b"{}")
        return DeliveryResult("sent", f"Accepted by Resend (id {body.get('id', '?')})")
    except urllib.error.HTTPError as e:
        try:
            why = str(json.loads(e.read()).get("message", ""))
        except Exception:
            why = ""
        return DeliveryResult("failed", f"Resend rejected the email (HTTP {e.code}): {why[:160]}".strip())
    except Exception as e:  # network, TLS, timeout ...
        return DeliveryResult("failed", f"{type(e).__name__}: {str(e)[:160]}")


def send_mail(to: str, subject: str, text: str, html: str) -> DeliveryResult:
    if settings.resend_api_key:
        return _send_https(to, subject, text, html)
    if not settings.smtp_configured:
        return DeliveryResult("not_configured", "E-mail is not configured (set SMTP_HOST, SMTP_USER and SMTP_PASSWORD, or RESEND_API_KEY, in .env). No email was sent.")
    try:
        msg = _message(to, subject, text, html)
        ctx = ssl.create_default_context()
        if settings.smtp_security == "ssl":
            with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=20, context=ctx) as s:
                s.login(settings.smtp_user, settings.smtp_password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as s:
                s.ehlo()
                if settings.smtp_security == "starttls":
                    s.starttls(context=ctx)
                    s.ehlo()
                s.login(settings.smtp_user, settings.smtp_password)
                s.send_message(msg)
        return DeliveryResult("sent", f"Accepted by {settings.smtp_host}")
    except smtplib.SMTPAuthenticationError:
        return DeliveryResult("failed", "SMTP login rejected — for Gmail use a 16-character App Password, not your account password.")
    except Exception as e:  # network, TLS, recipient refused ...
        return DeliveryResult("failed", f"{type(e).__name__}: {str(e)[:160]}")


# --------------------------------------------------------------------------------------- messages
def send_otp(to: str, code: str, ttl: int, username: str, purpose: str = "sign-in") -> DeliveryResult:
    """One-time verification code. `purpose` is shown to the reader: 'sign-in', 'registration', ..."""
    brand, expires = _brand(), _ttl_text(ttl)
    name = escape(username)
    body = f"""
<div style="font-size:12px;font-weight:700;letter-spacing:1.4px;color:{INDIGO};text-transform:uppercase">Verification code</div>
<h1 style="margin:6px 0 14px;font-size:24px;line-height:1.25;color:{INK}">Confirm your {escape(purpose)}</h1>
<p style="margin:0 0 20px;font-size:15px;line-height:1.6;color:#374151">Hi {name}, use the code below to complete your {escape(purpose)} with {escape(brand)}. It is valid for <b>{expires}</b> and works only once.</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center" style="background:#EEF2FF;border:1px solid #C7D2FE;border-radius:12px;padding:22px 12px">
 <div style="font-family:'SFMono-Regular',Consolas,'Courier New',monospace;font-size:38px;font-weight:700;letter-spacing:12px;color:{INDIGO_DARK};padding-left:12px">{escape(code)}</div>
 <div style="margin-top:8px;font-size:12px;color:{INDIGO_DARK}">Expires in {expires}</div>
</td></tr></table>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:22px">{_rows([("Account", username), ("Request", purpose.capitalize()), ("Time", _stamp())])}</table>
{_notice(f"<b>Didn&rsquo;t request this?</b> You can safely ignore this email &mdash; nobody can get in without the code. Never share it with anyone; {escape(brand)} staff will never ask for it.")}"""
    text = (f"{brand}\n\nConfirm your {purpose}\n\nHi {username},\n\nYour verification code is: {code}\n\n"
            f"It is valid for {expires} and works only once.\nRequested: {_stamp()}\n\n"
            f"Didn't request this? Ignore this email - nobody can get in without the code. "
            f"Never share it; {brand} staff will never ask for it.\n\n-- {brand} Security (automated message, do not reply)\n")
    html = _layout(f"{code} is your {brand} verification code", f"Your {brand} verification code is {code}. It expires in {expires}.", body)
    return send_mail(to, f"{code} is your {brand} verification code", text, html)


def send_order_receipt(to: str, name: str, order_no: str, lines: list[dict], total: int, paid_with: str) -> DeliveryResult:
    """Order confirmation. `lines` = [{name, qty, amount}] with amounts in whole rupees."""
    brand = _brand()
    inr = lambda n: f"₹{n:,}"  # noqa: E731
    rows = "".join(
        f'<tr><td style="padding:10px 0;font-size:14px;color:{INK};border-bottom:1px solid {LINE}">{escape(l["name"])}'
        f'<div style="font-size:12px;color:{MUTED}">Qty {l["qty"]}</div></td>'
        f'<td align="right" style="padding:10px 0;font-size:14px;color:{INK};font-weight:600;border-bottom:1px solid {LINE}">{inr(l["amount"])}</td></tr>' for l in lines)
    body = f"""
<div style="font-size:12px;font-weight:700;letter-spacing:1.4px;color:#059669;text-transform:uppercase">Order confirmed</div>
<h1 style="margin:6px 0 10px;font-size:24px;line-height:1.25;color:{INK}">Thanks for your order, {escape(name.split(' ')[0])}</h1>
<p style="margin:0 0 20px;font-size:15px;line-height:1.6;color:#374151">We&rsquo;ve received your payment and are getting your order ready. Here is your receipt.</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:6px">{_rows([("Order number", order_no), ("Date", _stamp()), ("Payment", paid_with)])}</table>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:14px">{rows}
 <tr><td style="padding:14px 0 0;font-size:15px;font-weight:700;color:{INK}">Total paid</td><td align="right" style="padding:14px 0 0;font-size:18px;font-weight:800;color:{INK}">{inr(total)}</td></tr></table>
{_notice("Every order record is digitally signed when it is created, so any later change to the amount can be detected.", "info")}"""
    text = (f"{brand} - order confirmed\n\nHi {name},\nthanks for your order {order_no}.\n\n"
            + "\n".join(f"  {l['name']} x{l['qty']}  {inr(l['amount'])}" for l in lines)
            + f"\n\nTotal paid: {inr(total)}\nPayment: {paid_with}\n\n-- {brand} (automated message, do not reply)\n")
    html = _layout(f"Your {brand} order {order_no}", f"Order {order_no} confirmed - total {inr(total)}.", body)
    return send_mail(to, f"Your {brand} order {order_no} is confirmed", text, html)


def send_security_alert(to: str, name: str, headline: str, detail: str, rows: list[tuple[str, str]] | None = None) -> DeliveryResult:
    brand = _brand()
    body = f"""
<div style="font-size:12px;font-weight:700;letter-spacing:1.4px;color:#DC2626;text-transform:uppercase">Security alert</div>
<h1 style="margin:6px 0 14px;font-size:24px;line-height:1.25;color:{INK}">{escape(headline)}</h1>
<p style="margin:0 0 18px;font-size:15px;line-height:1.6;color:#374151">Hi {escape(name)},<br>{escape(detail)}</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0">{_rows((rows or []) + [("Time", _stamp())])}</table>
{_notice("If this was you, no action is needed. If it wasn&rsquo;t, sign in and change your password right away.")}"""
    text = f"{brand} security alert\n\n{headline}\n\nHi {name},\n{detail}\nTime: {_stamp()}\n\n-- {brand} Security (automated message, do not reply)\n"
    return send_mail(to, f"{brand} security alert: {headline}", text, _layout(headline, detail[:90], body))


def send_test(to: str) -> DeliveryResult:
    brand = _brand()
    body = f"""
<div style="font-size:12px;font-weight:700;letter-spacing:1.4px;color:#059669;text-transform:uppercase">Email delivery</div>
<h1 style="margin:6px 0 14px;font-size:24px;line-height:1.25;color:{INK}">Your email is set up correctly</h1>
<p style="margin:0;font-size:15px;line-height:1.6;color:#374151">This test message confirms that {escape(brand)} can send email to this address. Sign-in codes and order receipts will arrive here.</p>"""
    text = f"{brand}\n\nYour email is set up correctly. Sign-in codes and order receipts will arrive at this address.\nSent: {_stamp()}\n"
    return send_mail(to, f"{brand}: email delivery test", text, _layout("Email delivery test", "Your email is set up correctly.", body))
