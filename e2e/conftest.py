"""Playwright end-to-end tests: boots the real stack (FastAPI + built dashboard) on a free port with a throw-away database."""
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PW = {"admin": "Admin#E2E-2026x", "analyst": "Analyst#E2E-2026x", "viewer": "Viewer#E2E-2026x", "shopper": "Shopper#E2E-2026x"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def base_url():
    if not (ROOT / "frontend" / "dist" / "index.html").exists():
        pytest.skip("frontend/dist missing - run `cd frontend && npm install && npm run build` first")
    import urllib.request
    tmp = tempfile.mkdtemp(prefix="cg-e2e-")
    port = _free_port()
    env = {**os.environ, "PORT": str(port), "HOST": "127.0.0.1", "DATA_DIR": tmp, "DATABASE_URL": f"sqlite:///{tmp}/e2e.db", "OTP_DEV_ECHO": "true",
           "TELEMETRY_ENABLED": "false", "CG_ADMIN_PASSWORD": PW["admin"], "CG_ANALYST_PASSWORD": PW["analyst"], "CG_VIEWER_PASSWORD": PW["viewer"], "CG_SHOPPER_PASSWORD": PW["shopper"],
           "SMTP_HOST": "", "SMTP_USER": "", "SMTP_PASSWORD": ""}
    proc = subprocess.Popen([sys.executable, str(ROOT / "run.py")], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            urllib.request.urlopen(url + "/api/health", timeout=1)
            break
        except Exception:
            time.sleep(0.25)
    else:
        proc.kill()
        pytest.fail("server did not start")
    yield url
    proc.terminate()


@pytest.fixture(scope="session")
def browser():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        chrome = os.environ.get("CHROME_PATH") or ("/usr/bin/google-chrome" if os.path.exists("/usr/bin/google-chrome") else None)
        b = p.chromium.launch(executable_path=chrome, headless=True, args=["--no-sandbox"]) if chrome else p.chromium.launch(headless=True)
        yield b
        b.close()


@pytest.fixture()
def page(browser, base_url):
    ctx = browser.new_context(viewport={"width": 1480, "height": 1000})
    pg = ctx.new_page()
    pg.errors = []
    pg.on("pageerror", lambda e: pg.errors.append(str(e)))
    pg.on("console", lambda m: pg.errors.append(m.text) if m.type == "error" and "401" not in m.text and "403" not in m.text and "409" not in m.text else None)
    pg.base = base_url
    yield pg
    ctx.close()


def type_code(pg):
    """Read the on-screen practice-mode code (SMTP is off in tests) and type it into the six boxes."""
    pg.wait_for_selector("text=Your code:", timeout=10000)
    code = pg.locator(".mono.text-xl.font-bold").first.inner_text().strip()
    for i, ch in enumerate(code):
        pg.locator(f"input[aria-label='Digit {i + 1}']").fill(ch)
    return code


def sign_in(pg, user="admin"):
    """Staff sign-in through the Security Centre login page."""
    pg.goto(pg.base + "/#/soc")
    pg.wait_for_selector("text=Security Centre sign-in")
    pg.select_option("select[aria-label=Account]", user)
    pg.fill("input[type=password]", PW[user])
    pg.click("text=Continue")
    pg.wait_for_selector("text=Enter your code")
    type_code(pg)
    pg.wait_for_selector("text=Live updates connected", timeout=15000)
    time.sleep(0.8)


@pytest.fixture()
def admin_page(page):
    sign_in(page, "admin")
    return page


# ---- helpers that talk to the API directly (to flip defences from "the security team" while a customer page is open)
_tok: dict = {}


def staff_api(base, path, body=None):
    import json
    import urllib.error
    import urllib.request

    def call(token):
        req = urllib.request.Request(base + "/api" + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
        return json.load(urllib.request.urlopen(req, timeout=15))

    def login():
        req = urllib.request.Request(base + "/api/auth/login", data=json.dumps({"username": "admin", "password": PW["admin"]}).encode(), headers={"Content-Type": "application/json"})
        j = json.load(urllib.request.urlopen(req, timeout=15))
        req = urllib.request.Request(base + "/api/auth/otp/verify", data=json.dumps({"challenge_id": j["challenge_id"], "code": j["delivery"]["dev_otp"]}).encode(), headers={"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=15))["token"]

    if "t" not in _tok:
        _tok["t"] = login()
    try:
        return call(_tok["t"])
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise
        _tok["t"] = login()
        return call(_tok["t"])


def set_defences(base, on: bool):
    staff_api(base, "/sim/mode", {"enabled": on})
