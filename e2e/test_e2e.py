import time

import pytest
from playwright.sync_api import expect

from conftest import PW, sign_in, type_code

PAGES = {"guide": "Guided Demo", "orders": "Store Orders & Fraud Review", "overview": "Security Overview", "attacks": "Attack Simulation", "topology": "Network Topology", "intel": "Threat Intelligence", "crypto": "Cryptography Laboratory",
         "signatures": "Digital Signature Verification", "iam": "Identity & Access Management", "database": "Database Security", "cia": "CIA Security Monitoring",
         "incidents": "Incident Response", "backup": "Backup & Recovery", "logs": "Security Audit Logs", "settings": "System Settings"}


def go(pg, page_id):
    pg.evaluate(f"location.hash = '#/soc/{page_id}'")
    time.sleep(0.9)


def set_all_defences(pg, on: bool):
    sw = pg.locator("button[aria-label='Enable all defences']")
    if (sw.get_attribute("aria-checked") == "true") != on:
        sw.click()
        time.sleep(1.0)


def test_login_wrong_password_rejected(page):
    page.goto(page.base + "/#/soc")
    page.fill("input[type=password]", "not-the-password")
    page.click("text=Continue")
    expect(page.locator("[role=alert]")).to_contain_text("Invalid username or password")


def test_otp_flow_wrong_then_correct_code(page):
    page.goto(page.base + "/#/soc")
    page.fill("input[type=password]", PW["admin"])
    page.click("text=Continue")
    page.wait_for_selector("text=Enter your code")
    expect(page.locator("text=Expires in")).to_be_visible()
    expect(page.locator("text=Send a new code in")).to_be_visible()  # cooldown is enforced
    code = page.locator(".mono.text-xl.font-bold").first.inner_text().strip()
    wrong = "000000" if code != "000000" else "111111"
    for i, ch in enumerate(wrong):
        page.locator(f"input[aria-label='Digit {i + 1}']").fill(ch)
    expect(page.locator("[role=alert]")).to_contain_text("2 attempts left")
    time.sleep(0.6)
    for i, ch in enumerate(code):
        page.locator(f"input[aria-label='Digit {i + 1}']").fill(ch)
    expect(page.locator("text=You're signed in")).to_be_visible(timeout=8000)
    expect(page.locator("text=Live updates connected")).to_be_visible(timeout=15000)
    assert not page.errors, page.errors


def test_unauthenticated_user_never_sees_the_console(page):
    page.goto(page.base + "/#/soc/database")
    expect(page.locator("text=Security Centre sign-in")).to_be_visible()


def test_all_15_pages_render_without_errors(admin_page):
    for pid, title in PAGES.items():
        go(admin_page, pid)
        expect(admin_page.locator("h1").first).to_have_text(title)
    assert not admin_page.errors, admin_page.errors


def test_attack_blocked_when_defences_are_on(admin_page):
    pg = admin_page
    go(pg, "attacks")
    set_all_defences(pg, True)
    pg.click("text=Launch attack")
    expect(pg.locator("text=ATTACK BLOCKED")).to_be_visible(timeout=25000)
    expect(pg.locator("text=Stopped at stage 2")).to_be_visible()
    assert not pg.errors, pg.errors


def test_attack_succeeds_when_defences_are_off_and_compare_works(admin_page):
    pg = admin_page
    go(pg, "attacks")
    pg.click("text=Compare OFF vs ON")
    expect(pg.locator("text=All 21 defences ON")).to_be_visible(timeout=10000)
    expect(pg.locator("text=BREACH").first).to_be_visible()
    pg.keyboard.press("Escape")
    set_all_defences(pg, False)
    pg.click("text=Launch attack")
    expect(pg.locator("text=SYSTEM BREACHED")).to_be_visible(timeout=30000)
    set_all_defences(pg, True)


def test_db_tamper_is_detected_and_restored(admin_page):
    pg = admin_page
    go(pg, "database")
    expect(pg.locator("text=All records verified")).to_be_visible()
    pg.click("text=Modify the record directly")
    pg.click("text=Yes, tamper")
    expect(pg.locator("text=TAMPERED").first).to_be_visible(timeout=8000)
    expect(pg.locator("text=Found in database")).to_be_visible()
    pg.click("text=Restore trusted version")
    expect(pg.locator("text=All records verified")).to_be_visible(timeout=8000)


def test_incident_lifecycle_through_the_ui(admin_page):
    pg = admin_page
    go(pg, "attacks")
    set_all_defences(pg, False)
    pg.locator("button", has_text="Database Value Tampering").first.click()
    pg.click("text=Launch attack")
    expect(pg.locator("text=SYSTEM BREACHED")).to_be_visible(timeout=30000)
    go(pg, "incidents")
    expect(pg.locator("text=INC-").first).to_be_visible()
    pg.wait_for_selector("[data-testid=advance]", timeout=8000)
    for _ in range(60):
        if pg.locator("[data-testid=advance]").count() == 0:  # a resolved incident has no advance button
            break
        btns = pg.locator("[data-testid=task-btn]")
        if btns.count():
            btns.first.click()
            time.sleep(0.5)
            continue
        notes = pg.locator("textarea[placeholder^='Root cause']")
        if notes.count() and not notes.input_value():
            notes.fill("Root cause: write access without an integrity gate. Fix: signed records + least-privilege DB grants.")
            pg.click("text=Save notes")
            time.sleep(0.6)
        adv = pg.locator("[data-testid=advance]")
        if adv.is_enabled():
            adv.click()
            time.sleep(0.7)
        else:
            time.sleep(0.4)
    expect(pg.locator("[data-testid=advance]")).to_have_count(0, timeout=10000)
    expect(pg.locator("text=Lessons learned").first).to_be_visible()
    go(pg, "database")
    expect(pg.locator("text=All records verified")).to_be_visible()
    go(pg, "cia")
    expect(pg.locator("text=db_tamper")).to_have_count(0, timeout=8000)  # this incident's damage is cleared
    set_all_defences(pg, True)


def test_crypto_lab_detects_tampering(admin_page):
    pg = admin_page
    go(pg, "crypto")
    pg.click("text=Encrypt with AES-256-GCM")
    expect(pg.locator("text=Ciphertext · unreadable")).to_be_visible()
    pg.click("text=Decrypt with the correct key")
    expect(pg.locator("text=Authentication tag VERIFIED")).to_be_visible()
    pg.click("text=Tamper: flip 1 bit of ciphertext")
    expect(pg.locator("text=Authentication tag MISMATCH")).to_be_visible()
    pg.click("text=Try a wrong key")
    expect(pg.locator("text=Authentication tag MISMATCH")).to_be_visible()


def test_signature_rejects_modified_record(admin_page):
    pg = admin_page
    go(pg, "signatures")
    pg.click("text=Generate key pair")
    expect(pg.locator("text=private key: not exposed")).to_be_visible(timeout=8000)
    pg.click("text=Sign record with private key")
    expect(pg.locator("text=Signature (")).to_be_visible()
    pg.click("text=Verify signature")
    expect(pg.get_by_text("SIGNATURE VALID", exact=True)).to_be_visible()
    pg.click("text=Simulate attacker: set value to 1")
    pg.click("text=Verify signature")
    expect(pg.get_by_text("SIGNATURE INVALID", exact=True)).to_be_visible()
    expect(pg.locator("text=Security alert raised")).to_be_visible()


def test_viewer_is_read_only(page):
    sign_in(page, "viewer")
    go(page, "attacks")
    expect(page.locator("button", has_text="Launch attack")).to_be_disabled()
    expect(page.locator("button[aria-label='Enable all defences']")).to_be_disabled()
    go(page, "database")
    page.click("text=Encrypted PII")
    expect(page.locator("text=Your role cannot decrypt PII")).to_be_visible()
    go(page, "iam")  # the server, not the UI, enforces RBAC: a real request with the viewer's token is refused
    page.locator("text=List all user accounts").locator("xpath=ancestor::div[contains(@class,'rounded-lg')][1]").get_by_role("button", name="Try").click()
    expect(page.locator("text=HTTP 403")).to_be_visible(timeout=8000)


def test_audit_chain_verifies(admin_page):
    go(admin_page, "logs")
    admin_page.click("text=Verify chain")
    expect(admin_page.locator("text=chain intact").first).to_be_visible(timeout=8000)


def test_watch_it_banner_jumps_to_the_live_attack(admin_page):
    """The red 'Attack running' banner has a 'Watch it' link; it must work even when you are already on the Attack Lab page."""
    pg = admin_page
    pg.set_viewport_size({"width": 1366, "height": 560})                 # a laptop-sized window: the pipeline starts below the fold
    go(pg, "attacks")
    set_all_defences(pg, False)
    pg.click("text=Launch attack")
    pg.wait_for_selector("[data-testid=watch-live]", timeout=10000)
    top_of = "document.getElementById('live-run').getBoundingClientRect().top"
    pg.evaluate("document.querySelector('main').scrollTo(0, 0)")
    time.sleep(0.4)
    before = pg.evaluate(top_of)
    assert before > 560, f"pipeline was already on screen before the click (top={before})"
    pg.click("[data-testid=watch-live]")
    time.sleep(1.3)                                                      # smooth scroll
    after = pg.evaluate(top_of)
    assert 0 <= after < 300, f"'Watch it' did not bring the pipeline into view (before={before}, after={after})"
    expect(pg.locator("text=SYSTEM BREACHED")).to_be_visible(timeout=30000)
    set_all_defences(pg, True)
    assert not pg.errors, pg.errors
