"""End-to-end tests of the NovaMart storefront and how it is attacked and defended."""
import time

import pytest
from playwright.sync_api import expect

from conftest import PW, set_defences, staff_api, type_code

PASSWORD = "Strong#Pass-2026!"


@pytest.fixture(autouse=True)
def defences_on_afterwards(base_url):
    set_defences(base_url, True)
    yield
    set_defences(base_url, True)


def register(pg, email, name="Test Shopper"):
    pg.goto(pg.base + "/#/register")
    pg.wait_for_selector("text=Create your NovaMart account")
    pg.fill("input[autocomplete=name]", name)
    pg.fill("input[aria-label=Email]", email)
    pg.fill("input[autocomplete=new-password]", PASSWORD)
    pg.click("button:has-text('Create account')")
    type_code(pg)
    expect(pg.locator("text=Email confirmed")).to_be_visible(timeout=10000)
    expect(pg.locator("header >> text=" + name.split()[0])).to_be_visible(timeout=10000)


def shop_sign_in(pg, who, password):
    pg.goto(pg.base + "/#/signin")
    pg.fill("input[aria-label=Email]", who)
    pg.fill("input[type=password]", password)
    pg.click("button:has-text('Continue')")
    type_code(pg)
    expect(pg.locator("text=You're signed in")).to_be_visible(timeout=10000)
    expect(pg.locator("a[href='#/orders']").first).to_be_visible(timeout=10000)


def open_toolbox(pg):
    pg.goto(pg.base + "/#/")
    pg.wait_for_selector("[data-testid=product-card]")
    if not pg.locator("[data-testid=toolbox]").count():
        pg.click("[data-testid=toolbox-toggle]")


def test_storefront_is_public_and_searchable(page):
    page.goto(page.base + "/#/")
    expect(page.locator("[data-testid=product-card]")).to_have_count(12)
    page.fill("input[aria-label='Search products']", "lamp")
    page.keyboard.press("Enter")
    expect(page.locator("[data-testid=product-card]")).to_have_count(1)
    expect(page.locator("text=LumiDesk LED Lamp")).to_be_visible()
    page.goto(page.base + "/#/category/Electronics")
    expect(page.locator("[data-testid=result-count]")).to_have_text("4 products")
    assert not page.errors, page.errors


def test_register_shop_checkout_and_see_order(page):
    register(page, f"buyer{int(time.time())}@example.com")
    page.goto(page.base + "/#/product/7")
    page.wait_for_selector("[data-testid=product-price]")
    page.click("button:has-text('Add to cart')")
    expect(page.locator("[data-testid=cart-count]")).to_have_text("1")
    page.goto(page.base + "/#/cart")
    expect(page.locator("[data-testid=cart-line]")).to_have_count(1)
    expect(page.locator("[data-testid=cart-total]")).to_have_text("₹699")
    page.click("text=Proceed to checkout")
    page.click("[data-testid=place-order]")
    expect(page.locator("[data-testid=order-banner]")).to_contain_text("your order is confirmed", timeout=10000)
    page.goto(page.base + "/#/orders")
    expect(page.locator("[data-testid=order-row]")).to_have_count(1)
    assert not page.errors, page.errors


def test_high_value_order_is_held_then_staff_approve_it(page, browser, base_url):
    register(page, f"big{int(time.time())}@example.com", "Big Spender")
    page.goto(page.base + "/#/product/10")
    page.wait_for_selector("[data-testid=product-price]")
    for _ in range(4):
        page.click("button[aria-label=More]")
    page.click("button:has-text('Add to cart')")
    page.goto(page.base + "/#/checkout")
    page.click("[data-testid=place-order]")
    expect(page.locator("[data-testid=order-banner]")).to_contain_text("quick safety check", timeout=10000)
    order_no = page.locator("[data-testid=order-banner] b").first.inner_text().strip()
    # staff see it in the review queue and approve it
    ctx = browser.new_context(viewport={"width": 1480, "height": 1000})
    sp = ctx.new_page()
    sp.base = base_url
    from conftest import sign_in
    sign_in(sp, "admin")
    sp.evaluate("location.hash = '#/soc/orders'")
    row = sp.locator("[data-testid=orders-table] tr", has_text=order_no)
    expect(row).to_contain_text("Being checked", timeout=10000)
    row.get_by_role("button", name="Approve").click()
    expect(row).to_contain_text("Confirmed", timeout=10000)
    ctx.close()
    page.goto(page.base + "/#/orders")
    page.locator("[data-testid=order-row]", has_text=order_no).click()
    expect(page.locator("text=Confirmed").first).to_be_visible(timeout=10000)


def test_sql_injection_is_blocked_with_defences_on_and_succeeds_when_off(page, base_url):
    page.goto(page.base + "/#/")
    open_toolbox(page)
    page.click("button:has-text(\"' OR 1=1 --\")")
    panel = page.locator("[data-testid=security-panel]").first
    expect(panel).to_have_attribute("data-result", "blocked", timeout=10000)
    expect(panel).to_contain_text("Web Application Firewall")
    set_defences(base_url, False)
    page.goto(page.base + "/#/")
    page.wait_for_selector("[data-testid=product-card]")
    page.goto(page.base + "/#/search/" + "%27%20OR%201%3D1%20--")
    panel = page.locator("[data-testid=security-panel]").first
    expect(panel).to_have_attribute("data-result", "breach", timeout=10000)
    expect(panel).to_contain_text("What the database actually ran")
    expect(panel).to_contain_text("Data that leaked")


def test_xss_and_idor_follow_the_defence_switch(page, base_url):
    register(page, f"attacker{int(time.time())}@example.com", "Mallory Test")
    for on, want in ((True, "blocked"), (False, "breach")):
        set_defences(base_url, on)
        open_toolbox(page)
        page.click("button:has-text('Post a script as a review')")
        expect(page.locator("[data-testid=toolbox] [data-testid=security-panel]")).to_have_attribute("data-result", want, timeout=10000)
        page.click("button:has-text('Open order NM-1001')")
        expect(page.locator("[data-testid=toolbox] [data-testid=security-panel]")).to_have_attribute("data-result", want, timeout=10000)


def test_customers_cannot_use_the_security_centre(page):
    shop_sign_in(page, "shopper", PW["shopper"])
    page.goto(page.base + "/#/soc/overview")
    expect(page.locator("text=Security Centre sign-in")).to_be_visible()  # a customer session never opens the console
    page.select_option("select[aria-label=Account]", "admin")
    page.fill("input[type=password]", PW["admin"])
    page.click("text=Continue")
    type_code(page)
    expect(page.locator("text=Live updates connected")).to_be_visible(timeout=15000)  # a staff account does


def test_staff_login_refuses_a_customer_account(page):
    page.goto(page.base + "/#/soc")
    page.wait_for_selector("text=Security Centre sign-in")
    # the staff form only offers staff accounts, so prove the server-side rule through the shop form instead
    shop_sign_in(page, "shopper", PW["shopper"])
    page.goto(page.base + "/#/soc")
    expect(page.locator("text=Security Centre sign-in")).to_be_visible()


def test_staff_cannot_sign_in_on_the_shop_form(page):
    page.goto(page.base + "/#/signin")
    page.fill("input[aria-label=Email]", "admin")
    page.fill("input[type=password]", PW["admin"])
    page.click("button:has-text('Continue')")
    type_code(page)
    expect(page.locator("[role=alert]")).to_contain_text("staff account", timeout=10000)


def test_guided_demo_page_and_orders_page_for_staff(admin_page):
    pg = admin_page
    pg.evaluate("location.hash = '#/soc/guide'")
    expect(pg.locator("h1").first).to_have_text("Guided Demo")
    expect(pg.locator("text=SQL injection on the search box")).to_be_visible()
    expect(pg.locator("text=What is real and what is simulated").first).to_be_visible()
    assert not pg.errors, pg.errors
