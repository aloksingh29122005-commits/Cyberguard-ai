"""Tests for the scam detector pages: checking, saving, alerts, privacy and who may see what."""
import json

from database.db import db
from models.alert import Alert
from models.scan import Scan
from models.user import User

PASSWORD = "StrongPass123"

SAFE_MESSAGE = "Hi Sam, are we still meeting at 6 pm near the library? Let me know if you want to change the time."

HIGH_MESSAGE = (
    "SBI ALERT: Your KYC has expired and your account will be blocked today. "
    "Update now: http://sbi-kyc-update.xyz/login and share the OTP you receive. Call 98765 43210."
)


def make_user(app, username="owner", email="owner@example.com"):
    with app.app_context():
        user = User(username=username, email=email)
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()
        return user.id


def log_in(client, email="owner@example.com"):
    return client.post("/login", data={"email": email, "password": PASSWORD}, follow_redirects=True)


def check(client, text, follow=True):
    return client.post("/scan/scam", data={"message_text": text}, follow_redirects=follow)


# ---------- Access ----------

def test_scam_pages_need_login(client):
    response = client.get("/scan/scam")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_scam_page_opens_and_sidebar_links_to_it(app, client):
    make_user(app)
    log_in(client)
    page = client.get("/scan/scam").get_data(as_text=True)
    assert "Check a message" in page
    assert "No message checks yet" in page
    assert 'href="/scan/scam"' in client.get("/dashboard").get_data(as_text=True)


# ---------- Checking ----------

def test_scam_message_is_saved_with_an_alert(app, client):
    make_user(app)
    log_in(client)
    page = check(client, HIGH_MESSAGE).get_data(as_text=True)

    assert "Scan result" in page
    assert "Message checked" in page
    assert "Check another message" in page
    assert "No link was opened and no reply was sent." in page
    assert "Link details" not in page  # that box is only for URL scans
    assert "sbi-kyc-update.xyz" in page  # the link that was found

    with app.app_context():
        saved = Scan.query.one()
        assert saved.scan_type == "scam"
        assert saved.target.startswith("Message: SBI ALERT: Your KYC has expired")
        assert saved.risk_score == 100
        assert saved.risk_level == "Critical"
        assert saved.is_demo is False

        alert = Alert.query.one()
        assert alert.severity == "Critical"
        assert alert.alert_type == "Scam message"
        assert alert.source == "Scam detector"
        assert alert.status == "Open"
        assert alert.scan_id == saved.id


def test_normal_message_raises_no_alert(app, client):
    make_user(app)
    log_in(client)
    page = check(client, SAFE_MESSAGE).get_data(as_text=True)
    assert "No warning signs found" in page
    with app.app_context():
        assert Scan.query.one().risk_score == 0
        assert Alert.query.count() == 0


def test_posting_redirects_to_the_result_page(app, client):
    make_user(app)
    log_in(client)
    response = check(client, SAFE_MESSAGE, follow=False)
    assert response.status_code == 302
    assert "/scan/" in response.headers["Location"]


def test_the_message_is_never_saved_and_long_numbers_are_hidden(app, client):
    make_user(app)
    log_in(client)
    check(client, "Hello there! Please keep code 482915 safe. my-private-sentence-4711")
    with app.app_context():
        saved = Scan.query.one()
        everything = saved.target + saved.explanation + json.dumps(saved.indicators)
        assert "482915" not in everything
        assert "my-private-sentence-4711" not in everything
        assert "****" in saved.target


def test_too_short_text_shows_an_error_and_saves_nothing(app, client):
    make_user(app)
    log_in(client)
    page = check(client, "hi").get_data(as_text=True)
    assert "too short to check" in page
    with app.app_context():
        assert Scan.query.count() == 0


def test_dashboard_shows_the_message_scan(app, client):
    make_user(app)
    log_in(client)
    check(client, HIGH_MESSAGE)
    page = client.get("/dashboard").get_data(as_text=True)
    assert "SBI ALERT" in page
    assert "Scam message" in page


def test_recent_checks_are_listed_with_a_link_to_the_result(app, client):
    make_user(app)
    log_in(client)
    check(client, SAFE_MESSAGE)
    page = client.get("/scan/scam").get_data(as_text=True)
    assert "are we still meeting" in page
    with app.app_context():
        assert f'href="/scan/{Scan.query.one().id}"' in page
    # each scanner has its own list
    assert "are we still meeting" not in client.get("/scan/email").get_data(as_text=True)


# ---------- Safety ----------

def test_a_message_scan_can_only_be_opened_by_its_owner(app, client):
    make_user(app, "first", "first@example.com")
    make_user(app, "second", "second@example.com")

    log_in(client, "first@example.com")
    check(client, HIGH_MESSAGE)
    with app.app_context():
        scan_id = Scan.query.one().id
    assert client.get(f"/scan/{scan_id}").status_code == 200

    other = app.test_client()
    log_in(other, "second@example.com")
    assert other.get(f"/scan/{scan_id}").status_code == 404


def test_scary_text_in_the_message_is_shown_as_text_never_as_script(app, client):
    make_user(app)
    log_in(client)
    page = check(client, "<script>alert(1)</script> you have won a prize, claim it").get_data(as_text=True)
    assert "<script>alert(1)" not in page
    assert "&lt;script&gt;" in page


def test_the_example_messages_on_the_page_do_not_break_it(app, client):
    make_user(app)
    log_in(client)
    page = client.get("/scan/scam").get_data(as_text=True)
    for example_id in ("example-safe", "example-medium", "example-high"):
        assert f'id="{example_id}"' in page