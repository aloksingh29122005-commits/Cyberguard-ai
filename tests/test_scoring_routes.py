"""Tests for the 'How scoring works' page and for the score breakdown on result pages."""
from markupsafe import escape

from database.db import db
from database.seed_demo import add_demo_data
from models.scan import Scan
from models.user import User
from services.risk_engine import THREAT_MIN_SCORE, get_rule_catalog

PASSWORD = "StrongPass123"

PHISHING_EMAIL = """From: "PayPal Support" <support@paypa1-secure.example>
Reply-To: helpdesk@gmail.com
Subject: URGENT: Your account will be suspended

Dear customer,

We noticed unusual activity on your account. You must verify your account within 24 hours or it will be suspended permanently.

Please confirm your password and OTP here: http://paypa1-secure.example/verify/login

Thank you,
Security Team"""


def make_user(app, username="owner", email="owner@example.com"):
    with app.app_context():
        user = User(username=username, email=email)
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()
        return user.id


def log_in(client, email="owner@example.com"):
    return client.post("/login", data={"email": email, "password": PASSWORD}, follow_redirects=True)


def scan_link(client, url):
    return client.post("/scan/url", data={"url": url}, follow_redirects=True).get_data(as_text=True)


# ---------- The scoring guide ----------

def test_the_scoring_guide_needs_login(client):
    response = client.get("/scan/scoring")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_the_scoring_guide_lists_every_rule_of_every_scanner(app, client):
    make_user(app)
    log_in(client)
    response = client.get("/scan/scoring")
    assert response.status_code == 200
    page = response.get_data(as_text=True)

    assert "How scoring works" in page
    for scanner in get_rule_catalog():
        assert str(escape(scanner["title"])) in page
        for rule in scanner["rules"]:
            assert str(escape(rule["name"])) in page, rule["code"]
            assert f"+{rule['points_text']}" in page


def test_the_scoring_guide_explains_the_levels_and_the_password_range(app, client):
    make_user(app)
    log_in(client)
    page = client.get("/scan/scoring").get_data(as_text=True)
    for level in ("Safe", "Low", "Medium", "High", "Critical"):
        assert level in page
    assert f"A score of {THREAT_MIN_SCORE} or more" in page
    assert "+5 to 45" in page  # the graded length rule of the password check
    assert "a higher score means a weaker password" in page


# ---------- The breakdown on result pages ----------

def test_a_phishing_email_shows_where_the_points_come_from(app, client):
    make_user(app)
    log_in(client)
    page = client.post("/scan/email", data={"email_text": PHISHING_EMAIL}, follow_redirects=True).get_data(as_text=True)

    assert "Where the points come from" in page
    assert "Pretending to be someone else" in page
    assert "Stealing logins or codes" in page
    assert "Main concern: <strong>Pretending to be someone else</strong>" in page
    assert "How the score adds up: 30 + 25 + 25 + 15 + 15 + 15 + 15 + 10 = 150, limited to 100" in page
    assert 'href="/scan/scoring"' in page


def test_one_kind_of_danger_shows_a_main_concern_but_no_chart(app, client):
    make_user(app)
    log_in(client)
    page = scan_link(client, "http://example.org/")
    assert "Main concern: <strong>Dangerous links</strong>" in page
    assert "Where the points come from" not in page
    assert "How the score adds up: 15 = 15" in page


def test_a_safe_scan_has_no_main_concern(app, client):
    make_user(app)
    log_in(client)
    page = scan_link(client, "https://docs.python.org/3/")
    assert "No warning signs found" in page
    assert "How the score adds up" not in page  # there is nothing to add up
    assert "Main concern" not in page
    assert "Where the points come from" not in page


def test_a_password_result_has_no_main_concern_and_no_chart(app, client):
    make_user(app)
    log_in(client)
    page = client.post("/scan/password", data={"password": "password123"}, follow_redirects=True).get_data(as_text=True)
    assert "Password strength" in page
    assert "Main concern" not in page
    assert "Where the points come from" not in page


def test_old_demo_scans_without_codes_still_open(app, client):
    user_id = make_user(app)
    log_in(client)
    with app.app_context():
        add_demo_data(user_id)
        scan_id = Scan.query.filter_by(user_id=user_id).order_by(Scan.id).first().id
    response = client.get(f"/scan/{scan_id}")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Warning signs found" in page
    assert "How the score adds up: 20 + 15 + 15 = 50" in page
    assert "Main concern" not in page