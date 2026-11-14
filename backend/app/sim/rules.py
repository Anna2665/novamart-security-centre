"""Pure, testable security rules that the defences evaluate. Nothing here touches the network or any real system."""
import html
import math
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass


# ---- WAF -----------------------------------------------------------------------------------------------------------
@dataclass
class Rule:
    id: str
    name: str


_SQLI = [
    (r"(?i)\bunion\b[\s\S]{0,40}\bselect\b", Rule("942100", "SQLi: UNION SELECT")),
    (r"(?i)'\s*(or|and)\s*'?\w*'?\s*=\s*'?\w*", Rule("942110", "SQLi: tautology (' OR '1'='1)")),
    (r"(?i)'\s*(or|and)\s+\d+\s*=\s*\d+", Rule("942111", "SQLi: numeric tautology")),
    (r"(--|#|/\*)\s*$|;\s*--", Rule("942120", "SQLi: comment terminator")),
    (r"(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\b", Rule("942130", "SQLi: time-based blind")),
    (r"(?i);\s*(drop|delete|insert|update)\b", Rule("942140", "SQLi: stacked query")),
]
_XSS = [
    (r"(?i)<\s*script", Rule("941100", "XSS: <script> tag")),
    (r"(?i)\bon\w+\s*=", Rule("941110", "XSS: inline event handler")),
    (r"(?i)javascript\s*:", Rule("941120", "XSS: javascript: URI")),
    (r"(?i)<\s*(iframe|img|svg)[^>]*(src|onload)", Rule("941130", "XSS: injected element")),
]


def waf_sqli(payload: str) -> Rule | None:
    return next((r for rx, r in _SQLI if re.search(rx, payload)), None)


def waf_xss(payload: str) -> Rule | None:
    return next((r for rx, r in _XSS if re.search(rx, payload)), None)


# ---- input handling --------------------------------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{3,64}$")


def validate_username(u: str) -> bool:
    return bool(USERNAME_RE.match(u))


def sanitise_html(s: str) -> str:
    s = re.sub(r"(?is)<\s*(script|iframe|object|embed)[^>]*>.*?<\s*/\s*\1\s*>", "", s)
    s = re.sub(r"(?i)\bon\w+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "", s)
    return html.escape(re.sub(r"(?i)javascript\s*:", "", s))


def encode_output(s: str) -> str:
    return html.escape(s, quote=True)


# ---- CSP ---------------------------------------------------------------------------------------------------------------
CSP_STRICT = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
CSP_NONE = "(no Content-Security-Policy header)"


def csp_allows_inline_script(header: str | None) -> bool:
    if not header or header == CSP_NONE:
        return True
    d = {}
    for part in header.split(";"):
        bits = part.strip().split()
        if bits:
            d[bits[0].lower()] = bits[1:]
    src = d.get("script-src", d.get("default-src"))
    if src is None:
        return True
    return "'unsafe-inline'" in src or "*" in src


# ---- CSRF ----------------------------------------------------------------------------------------------------------------
def csrf_evaluate(req: dict, cfg: dict) -> dict:
    """req: method/origin/site/csrf_token; cfg: samesite, token_required, allowed_origins, session_token."""
    cross_site = req["origin"] not in cfg["allowed_origins"]
    cookie_sent = not (cross_site and cfg["samesite"] in ("Lax", "Strict") and req["method"] != "GET") if cfg["samesite"] != "None" else True
    if cfg["samesite"] == "Lax" and cross_site and req["method"] == "GET":
        cookie_sent = True
    checks = [
        {"check": f"SameSite={cfg['samesite']} cookie attached to cross-site POST", "ok": not cookie_sent,
         "detail": "browser withholds the session cookie" if not cookie_sent else "cookie would be sent with the forged request"},
        {"check": "Origin header on allow-list", "ok": (not cross_site) if cfg["origin_check"] else False,
         "detail": f"Origin {req['origin']} {'allowed' if not cross_site else 'rejected'}" if cfg["origin_check"] else "Origin not checked"},
        {"check": "Anti-CSRF token matches session", "ok": (req.get("csrf_token") == cfg["session_token"]) if cfg["token_required"] else False,
         "detail": ("token missing/invalid" if req.get("csrf_token") != cfg["session_token"] else "token valid") if cfg["token_required"] else "no token required"},
    ]
    # request is rejected if ANY enabled protection rejects it
    rejected = (cfg["samesite"] != "None" and not cookie_sent) or (cfg["origin_check"] and cross_site) or \
               (cfg["token_required"] and req.get("csrf_token") != cfg["session_token"])
    return {"allowed": not rejected, "checks": checks, "cookie_sent": cookie_sent}


# ---- phishing -----------------------------------------------------------------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


def phish_score(email: dict, brand: str = "novamart.com") -> dict:
    """Heuristic scoring of an email header/body. Returns indicators and a 0-100 score (>=60 quarantined)."""
    dom = email["from"].split("@")[-1].lower()
    norm = dom.translate(_HOMO).replace("-secure", "").replace("secure-", "")
    dist = levenshtein(norm.split(".")[0], brand.split(".")[0])
    link_host = re.sub(r"^https?://", "", email["link"]).split("/")[0].lower()
    inds = [
        ("Look-alike sender domain", dom != brand and (dist <= 3 or brand.split(".")[0] in dom), 30, f"{dom} vs {brand} (edit distance {dist})"),
        ("SPF check", email["spf"] != "pass", 15, f"spf={email['spf']}"),
        ("DKIM signature", email["dkim"] != "pass", 15, f"dkim={email['dkim']}"),
        ("DMARC alignment", email["dmarc"] != "pass", 10, f"dmarc={email['dmarc']}"),
        ("Link text ≠ destination", link_host != email["link_text_host"], 20, f"shows {email['link_text_host']} but goes to {link_host}"),
        ("Urgency / credential language", bool(re.search(r"(?i)urgent|suspend|verify|within 24|locked", email["body"])), 10, "urgent + 'verify account' wording"),
    ]
    rows = [{"indicator": n, "flagged": f, "points": p if f else 0, "detail": d} for n, f, p, d in inds]
    return {"score": min(100, sum(r["points"] for r in rows)), "indicators": rows, "threshold": 60}


# ---- DLP / entropy --------------------------------------------------------------------------------------------------------
PII_PATTERNS = {"email": r"[\w.+-]+@[\w-]+\.[\w.]+", "phone": r"\+91[\s-]?\d{5}[\s-]?\d{5}", "card": r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"}


def pii_scan(text: str) -> dict[str, int]:
    return {k: len(re.findall(rx, text)) for k, rx in PII_PATTERNS.items()}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


# ---- mock vulnerable shop DB (isolated, in-memory, read-only) ----------------------------------------------------------------
MOCK_USERS = [
    (1, "admin", "Rhea Kapoor", "admin", "rhea.kapoor@novamart.example"),
    (2, "arjun.m", "Arjun Mehta", "customer", "arjun.m@example.com"),
    (3, "sneha.k", "Sneha Kulkarni", "customer", "sneha.k@example.com"),
    (4, "farhan.s", "Farhan Sheikh", "customer", "farhan.s@example.com"),
    (5, "divya.r", "Divya Rao", "customer", "divya.r@example.com"),
    (6, "kiran.p", "Kiran Pillai", "customer", "kiran.p@example.com"),
]
import hashlib  # noqa: E402


def _h(p: str) -> str:
    return hashlib.sha256(("novamart-demo-salt:" + p).encode()).hexdigest()


def _mockdb() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users (id INTEGER, username TEXT, full_name TEXT, role TEXT, email TEXT, password_hash TEXT)")
    for u in MOCK_USERS:
        c.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", (*u, _h(f"pw-{u[1]}-!x9")))
    c.commit()
    c.execute("PRAGMA query_only = ON")  # the mock DB can never be written to, even by a clever payload
    return c


def mock_login(username: str, password: str, mode: str) -> dict:
    """mode 'unsafe': string-built SQL (vulnerable on purpose, isolated mock). mode 'parameterised': bound parameters."""
    conn = _mockdb()
    pw = _h(password)
    try:
        if mode == "unsafe":
            sql = f"SELECT id, username, role, email FROM users WHERE username = '{username}' AND password_hash = '{pw}'"
            rows = conn.execute(sql).fetchall()
            shown = sql.replace(pw, "<sha256(password)>")
            params = None
        else:
            sql = "SELECT id, username, role, email FROM users WHERE username = ? AND password_hash = ?"
            rows = conn.execute(sql, (username, pw)).fetchall()
            shown, params = sql, [username, "<sha256(password)>"]
        return {"mode": mode, "query": shown, "params": params, "rows": [list(r) for r in rows], "row_count": len(rows),
                "authenticated": len(rows) > 0, "error": None}
    except sqlite3.Error as e:
        return {"mode": mode, "query": sql if mode == "unsafe" else "", "params": None, "rows": [], "row_count": 0,
                "authenticated": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        conn.close()


# ---- storefront search: isolated vulnerable mock ---------------------------------------------------------------------
def mock_search(q: str, catalogue: list[tuple[int, str, str, int]]) -> dict:
    """The store's search box as it WOULD behave if the query were built by string concatenation.

    Runs only on a throw-away in-memory copy of the catalogue plus fictional hidden rows and fictional users, opened
    read-only, so even a clever payload can neither change nor reach any real data.
    """
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE products (id INTEGER, name TEXT, category TEXT, price INTEGER, visible INTEGER)")
    conn.executemany("INSERT INTO products VALUES (?,?,?,?,1)", catalogue)
    conn.execute("INSERT INTO products VALUES (901,'[INTERNAL] Staff 90% discount voucher','Internal',1,0)")
    conn.execute("INSERT INTO products VALUES (902,'[UNRELEASED] PixelPad Max prototype','Internal',99999,0)")
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, full_name TEXT, role TEXT, email TEXT, password_hash TEXT)")
    for u in MOCK_USERS:
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", (*u, _h(f"pw-{u[1]}-!x9")))
    conn.commit()
    conn.execute("PRAGMA query_only = ON")
    sql = f"SELECT id, name, category, price FROM products WHERE visible = 1 AND name LIKE '%{q}%'"
    try:
        rows = [dict(zip(("id", "name", "category", "price"), r)) for r in conn.execute(sql).fetchall()]
        visible = {(i, n) for i, n, _, _ in catalogue}
        leaked = [r for r in rows if (r["id"], r["name"]) not in visible]
        return {"query": sql, "rows": rows, "leaked": leaked, "error": None}
    except sqlite3.Error as e:
        return {"query": sql, "rows": [], "leaked": [], "error": f"{type(e).__name__}: {e}"}
    finally:
        conn.close()
